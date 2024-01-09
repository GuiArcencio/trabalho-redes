from __future__ import annotations
from ipaddress import ip_address
import struct
from random import randint

from iputils import *
from tcputils import *

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.identification = randint(0, 2**16 - 1)

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            novo_ttl = ttl - 1
            tam_cabecalho = len(datagrama) - len(payload)

            if novo_ttl > 0:
                datagrama = bytearray(datagrama)
                datagrama[8:9] = struct.pack('!B', novo_ttl)
                datagrama[10:12] = b'\x00\x00'

                novo_cabecalho = self._corrigir_checksum_ipv4(bytes(datagrama[:tam_cabecalho]))
                self.enlace.enviar(novo_cabecalho + payload, next_hop)
            else: # Time exceeded
                cabecalho_icmp = self._montar_cabecalho_icmp(11, 0, 0)
                segmento_retorno = cabecalho_icmp + datagrama[:(tam_cabecalho + 8)]
                cabecalho_ipv4 = self._montar_cabecalho_ipv4(
                    src_addr, 
                    len(segmento_retorno),
                    IPPROTO_ICMP,
                    64
                )
                return_hop = self._next_hop(src_addr)
                self.enlace.enviar(cabecalho_ipv4 + segmento_retorno, return_hop)

    def _next_hop(self, dest_addr):
        ip = self._ipaddr_para_bitstring(dest_addr)
        return self._tabela_encaminhamento.find(ip)

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self._tabela_encaminhamento = TRIE()
        for cidr, next_hop in tabela:
            self._tabela_encaminhamento.insert(
                self._cidr_para_bitstring(cidr),
                next_hop
            )

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        # Montagem de cabeçalho
        version__ihl = (4 << 4) + 5
        dscp__ecn = 0
        total_length = 20 + len(segmento)
        identification = self.identification
        flags__fragment_offset = 0
        ttl = 64
        protocol = IPPROTO_TCP
        header_checksum = 0
        src_addr = int.from_bytes(ip_address(self.meu_endereco).packed, 'big')
        dest_addr = int.from_bytes(ip_address(dest_addr).packed, 'big')

        cabecalho = self._montar_cabecalho_ipv4(
            dest_addr,
            len(segmento), 
            IPPROTO_TCP,
            64
        )

        datagrama = cabecalho + segmento
        self.enlace.enviar(datagrama, next_hop)
        self.identification = (self.identification + 1) % (2**16)

    def _cidr_para_bitstring(self, cidr: str):
        ip, bits = cidr.split('/')
        bits = int(bits)
        ip = int.from_bytes(ip_address(ip).packed, 'big')
        ip = f'{ip:032b}'[:bits]

        return ip 
    
    def _ipaddr_para_bitstring(self, ipaddr: str):
        ip = int.from_bytes(ip_address(ipaddr).packed, 'big')
        return f'{ip:032b}'
    
    def _corrigir_checksum_ipv4(self, cabecalho: bytes):
        header_checksum = calc_checksum(cabecalho)
        cabecalho = bytearray(cabecalho)
        cabecalho[10:12] = struct.pack('!H', header_checksum)
        return bytes(cabecalho)
    
    def _corrigir_checksum_icmp(self, cabecalho: bytes):
        header_checksum = calc_checksum(cabecalho)
        cabecalho = bytearray(cabecalho)
        cabecalho[2:4] = struct.pack('!H', header_checksum)
        return bytes(cabecalho)
    
    def _montar_cabecalho_ipv4(self, dest_addr, tam_payload, protocol, ttl=64):
        version__ihl = (4 << 4) + 5
        dscp__ecn = 0
        total_length = 20 + tam_payload
        identification = self.identification
        flags__fragment_offset = 0
        header_checksum = 0
        src_addr = int.from_bytes(ip_address(self.meu_endereco).packed, 'big')
        dest_addr = int.from_bytes(ip_address(dest_addr).packed, 'big')

        cabecalho = struct.pack(
            '!BBHHHBBHII',
            version__ihl,
            dscp__ecn,
            total_length,
            identification,
            flags__fragment_offset,
            ttl,
            protocol,
            header_checksum,
            src_addr,
            dest_addr
        )
        return self._corrigir_checksum_ipv4(cabecalho)
    
    def _montar_cabecalho_icmp(self, type, code, rest):
        cabecalho = struct.pack(
            '!BBHI',
            type,
            code,
            0, # Checksum,
            rest,
        )
        return self._corrigir_checksum_icmp(cabecalho)


# Implementação de TRIE para a tabela de encaminhamento
class TRIE:
    _content: str | None
    _one_child: TRIE
    _zero_child: TRIE

    def __init__(self, content: str | None = None) -> None:
        self._content = content
        self._one_child = None
        self._zero_child = None

    def find(self, key: str):
        found = self._content
        found_child = None

        if len(key) > 0:
            if key[0] == '0' and self._zero_child is not None:
                found_child = self._zero_child.find(key[1:])
            elif key[0] == '1' and self._one_child is not None:
                found_child = self._one_child.find(key[1:])

        if found_child is not None:
            return found_child
        return found

    def insert(self, key: str, content: str):
        if len(key) == 0:
            self._content = content
            return
        
        if key[0] == '0':
            if self._zero_child is None:
                self._zero_child = TRIE()

            self._zero_child.insert(key[1:], content)
        elif key[0] == '1':
            if self._one_child is None:
                self._one_child = TRIE()

            self._one_child.insert(key[1:], content)