import asyncio
from random import randint
from time import time
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, window_size)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))
            
    def remover_conexao(self, id_conexao):
        self.conexoes.pop(id_conexao, None)

ALPHA = 0.125
BETA = 0.25
class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, window_size):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = None
        self.unacked_segments = []
        self.fila_de_envio = []
        self.estimated_rtt = None
        self.dev_rtt = None
        self.current_window_size = 1 # * MSS
        self.current_seq_no = randint(0, 0xffff)
        self.last_acked_no = self.current_seq_no
        self.expected_seq_no = seq_no + 1
        self.prestes_a_fechar = False
        self.handshake_completo = False

        # Responde com SYNACK para a abertura de conexão
        self._enviar_segmento(
            FLAGS_SYN | FLAGS_ACK,
            b'',
        )

    def _timeout_interval(self):
        """
        Calcula o timeout com base no RTT estimado
        """
        if self.estimated_rtt is None:
            return 3
        else:
            return self.estimated_rtt + 4 * self.dev_rtt
        
    def _estimar_rtt(self, sample_rtt):
        """
        Nova estimativa para o RTT
        """
        if not self.handshake_completo:
            # Não use o ACK de abertura de conexão para estimar
            self.handshake_completo = True
            return

        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            self.estimated_rtt = (1-ALPHA) * self.estimated_rtt + ALPHA * sample_rtt
            self.dev_rtt = (1-BETA) * self.dev_rtt + BETA * abs(sample_rtt - self.estimated_rtt)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        print('recebido payload: %r' % payload)

        # Fechamento de conexão
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.expected_seq_no += 1
            self._enviar_segmento(
                FLAGS_ACK,
                b''
            )
            self.callback(self, b'')
            return

        # Um ACK
        if (flags & FLAGS_ACK) == FLAGS_ACK:
            # Um novo pacote foi ACKED!
            if ack_no > self.last_acked_no:
                if self.timer is not None:
                    self.timer.cancel()
                    self.timer = None

                self.last_acked_no = ack_no
                # Ajusta o tamanho da janela com o novo ACK
                if self.handshake_completo:
                    self.current_window_size += 1

                # Verifica se algum dos pacotes enviados
                # ainda não foi reconhecido
                smallest_unacked_segment_idx = None
                for i, (unacked_seq_no, _, _, _) in enumerate(self.unacked_segments):
                    if unacked_seq_no > self.last_acked_no - 1:
                        smallest_unacked_segment_idx = i
                        break

                # Todos os pacotes enviados já foram reconhecidos
                if smallest_unacked_segment_idx is None:
                    if not self.unacked_segments[-1][3]:
                        # Um pacote não-retransmitido foi reconhecido,
                        # então deve-se estimar o novo RTT
                        self._estimar_rtt(time() - self.unacked_segments[-1][2])

                    self.unacked_segments = []
                # Ainda há pacotes sem um ACK
                else:
                    if i > 0 and not self.unacked_segments[i-1][3]:
                        # Um pacote não-retransmitido foi reconhecido,
                        # então deve-se estimar o novo RTT
                        self._estimar_rtt(time() - self.unacked_segments[i-1][2])

                    self.unacked_segments = self.unacked_segments[i:]
                    self.timer = asyncio.get_event_loop().call_later(self._timeout_interval(), self._resend_timer)

                # Com um ACK, podemos tentar enviar o que está na fila
                self._enviar_fila()

            # ACK do fechamento
            if self.prestes_a_fechar:
                self.servidor.remover_conexao(self.id_conexao)
                return

            # Não precisa responder com um ACK se foi só um ACK vazio
            if len(payload) == 0:
                return

        if seq_no == self.expected_seq_no:
            self.expected_seq_no += len(payload)
            self.callback(self, payload)

        self._enviar_segmento(
            FLAGS_ACK,
            b'',
        )

    def _calcular_bytes_inflight(self):
        if len(self.unacked_segments) == 0:
            return 0
        else:
            return self.unacked_segments[-1][0] - self.last_acked_no + 1
    
    def _enviar_segmento(self, flags, payload):
        """
        Adiciona um segmento à fila de envio
        """

        # Separa os dados em pacotes de 1MSS
        while len(payload) > MSS:
            self.fila_de_envio.append((self.current_seq_no, flags, payload[:MSS]))
            self.current_seq_no += MSS
            payload = payload[MSS:]

        self.fila_de_envio.append((self.current_seq_no, flags, payload))
        self.current_seq_no += len(payload)
        if len(payload) == 0 and ((flags & FLAGS_SYN) == FLAGS_SYN or (flags & FLAGS_FIN) == FLAGS_FIN):
            self.current_seq_no += 1

        # Tenta enviar o que já está na fila
        self._enviar_fila()

    def _enviar_fila(self):
        while len(self.fila_de_envio) > 0 and self._calcular_bytes_inflight() + len(self.fila_de_envio[0][2]) <= self.current_window_size * MSS:
            seq_no, flags, payload = self.fila_de_envio.pop(0)

            segment = make_header(
                self.id_conexao[3],
                self.id_conexao[1],
                seq_no,
                self.expected_seq_no,
                flags,
            )
            segment = segment + payload
            segment = fix_checksum(
                segment,
                self.id_conexao[2],
                self.id_conexao[0]
            )

            self.unacked_segments.append((seq_no, segment, time(), False))
            self.servidor.rede.enviar(segment, self.id_conexao[0])

            if self.timer is None:
                self.timer = asyncio.get_event_loop().call_later(self._timeout_interval(), self._resend_timer)

    def _resend_timer(self):
        if len(self.unacked_segments) > 0:
            # Houve uma perda! Devemos diminuir a janela pela metade
            self.current_window_size = max(1, self.current_window_size // 2)

            self.servidor.rede.enviar(self.unacked_segments[0][1], self.id_conexao[0])
            self.unacked_segments[0] = (*self.unacked_segments[0][:3], True)
        
        self.timer = asyncio.get_event_loop().call_later(self._timeout_interval(), self._resend_timer)


    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        self._enviar_segmento(
            FLAGS_ACK,
            dados
        )

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        self.prestes_a_fechar = True
        self._enviar_segmento(
            FLAGS_FIN,
            b'',
        )
