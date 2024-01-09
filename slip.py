class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)

ESTADO_OCIOSO = 0
ESTADO_LENDO = 1
ESTADO_ESCAPE = 2

class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.buffer = b''
        self.estado = ESTADO_OCIOSO

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        quadro = b''
        for byte in bytearray(datagrama):
            byte = byte.to_bytes(1, 'big', signed=False)
            
            if byte == b'\xC0':
                quadro = quadro + b'\xDB\xDC'
            elif byte == b'\xDB':
                quadro = quadro + b'\xDB\xDD'
            else:
                quadro = quadro + byte

        quadro = b'\xC0' + quadro + b'\xC0'
        self.linha_serial.enviar(quadro)

    def __raw_recv(self, dados):
        for byte in dados:
            byte = byte.to_bytes(1, 'big', signed=False)
            if self.estado == ESTADO_OCIOSO:
                if byte == b'\xDB':
                    self.estado = ESTADO_ESCAPE
                elif byte == b'\xC0':
                    self.estado = ESTADO_LENDO
                else:
                    self.buffer = self.buffer + byte
                    self.estado = ESTADO_LENDO
            elif self.estado == ESTADO_LENDO:
                if byte == b'\xC0':
                    if len(self.buffer) > 0: # Ignorando quadros vazios
                        try:
                            self.callback(self.buffer)
                        except:
                            # ignora a exceção, mas mostra na tela
                            import traceback
                            traceback.print_exc()

                    self.buffer = b''
                    self.estado = ESTADO_OCIOSO
                elif byte == b'\xDB':
                    self.estado = ESTADO_ESCAPE
                else:
                    self.buffer = self.buffer + byte
            elif self.estado == ESTADO_ESCAPE:
                if byte == b'\xDC':
                    self.buffer = self.buffer + b'\xC0'
                elif byte == b'\xDD':
                    self.buffer = self.buffer + b'\xDB'

                self.estado = ESTADO_LENDO
