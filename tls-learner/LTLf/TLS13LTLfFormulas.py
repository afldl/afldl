TLS13_formulas = {
    #--------------
    # bug pattern
    #--------------
    'bug_1' : 'G(server_certreq -> WX(client_cert R !(client_appdata & WX server_appdata)))',
    'bug_2' : 'G(client_cert -> WX(client_certver R !(client_appdata & WX server_appdata)))',
    'bug_3' : 'G(client_closure_alert -> WXG((client_closure_alert | other_inp) -> WX no_response))',
    'bug_4' : 'G(client_error_alert -> WXG((client_error_alert | other_inp) -> WX no_response))',
    'bug_5' : '(clienthello -> WX(server_cert R !server_finsihed))',
    'bug_6' : '(clienthello -> WXG(server_cert -> WX G! server_cert))',
    'bug_7' : '(clienthello -> WX(server_certver R !server_finsihed))',
    'bug_7' : '(clienthello -> WXG(server_ccs -> WX G! server_ccs))',
    
    #--------------
    # rfc
    #--------------
    # 1.Application Data MUST NOT be sent prior to sending the Finished message, except as specified in Section 2.3.
    'formula_1' : '(clienthello -> WX(server_finished R !(client_appdata & WX server_appdata)))',
    # 2.Implementations MUST NOT send extension responses if the remote endpoint did not send the corresponding extension requests, with the exception of the "cookie" extension in the HelloRetryRequest.
    # The server MUST NOT send a "psk_key_exchange_modes" extension.
    # Servers MUST NOT send a KeyShareEntry for any group not indicated in the client’s "supported_groups" extension and MUST NOT send a KeyShareEntry when using the "psk_ke" PskKeyExchangeMode.
    # Servers MUST NOT select a key exchange mode that is not listed by the client.
    'formula_2' : '(clienthello -> WX !F(serverhello_with_wrong_ens | en_extensions_with_wrong_ens | helloretryrequest_with_wrong_ens))',
    # 4.Servers MUST NOT send a post-handshake CertificateRequest to clients which do not offer this extension. Servers MUST NOT send this extension.
    'formula_4' : '(clienthello -> WX !F(server_certreq_ph))',
    # 8.Servers which are authenticating with a PSK MUST NOT send the CertificateRequest message in the main handshake, though they MAY send it in post-handshake authentication.
    'formula_8' : '(clienthello -> WX (serverhello_with_psk -> WXG !server_certreq))',
    # 9.Servers MUST NOT send this message(End of Early Data), and clients receiving it MUST terminate the connection with an "unexpected_message" alert.
    'formula_9' : '(clienthello -> WX !F(server_end_of_early))',
    # 10.Servers MUST NOT use any value greater than 604800 seconds (7 days).
    'formula_10' : 'clienthello -> G(client_finsihed -> WX !F new_session_ticket_with_wrong_lifetime)',
    # 11.Note that Application Data records MUST NOT be written to the wire unprotected.
    'formula_11' : '(clienthello R !server_finished) & G(server_finsihed -> WX !F(server_appdata_unprotected))',
    # 12. Because TLS 1.3 forbids renegotiation, if a server has negotiated TLS 1.3 and receives a ClientHello at any other time, it MUST terminate the connection with an "unexpected_message" alert.
    'formula_12' : 'clienthello -> WX G(clienthello -> WX (unexpected_message | no_response))',
    # 13. In all handshakes, the server MUST send the EncryptedExtensions message immediately after the ServerHello message.
    'formula_13' : 'clienthello -> WX G(serverhello -> XF en_extensions)',
    # 14. A server which is authenticating with a certificate MAY optionally request a certificate from the client. This message, if sent, MUST follow EncryptedExtensions.
    'formula_14' : 'clienthello -> WX(en_extensions R !server_certreq)',
}

client_sut_to_ltl_map = {
    'ClientHello' : 'clienthello',
    'ClientHelloNoPostHandshakeEN' : 'clienthello_no_pha_en',
    'ChangeCipherSpec' : 'client_ccs',
    'Certificate' : 'client_cert',
    'CertificateVerify' : 'client_certver',
    'Finish' : 'client_finished', 
    'ApplicationData' : 'client_appdata',
    'ClosureAlert' : 'client_closure_alert',
    'ErrorAlert' : 'client_error_alert',
    'CertificateRequest' : 'client_certreq',
}

client_ltl_to_sut_map = {
    'clienthello' : 'ClientHello',
    'clienthello_no_pha_en' : 'ClientHelloNoPostHandshakeEN',
    'client_ccs' : 'ChangeCipherSpec',
    'client_cert' : 'Certificate',
    'client_certver' : 'CertificateVerify',
    'client_finished' : 'Finish', 
    'client_appdata' : 'ApplicationData',
    'client_closure_alert' : 'ClosureAlert',
    'client_error_alert' : 'ErrorAlert',
    'client_certreq' : 'CertificateRequest',
}

server_sut_to_ltl_map = {
    'ServerHello' : 'serverhello',
    'ServerHelloPSK' : 'serverhello_with_psk',
    'ServerHelloWithWrongENs' : 'serverhello_with_wrong_ens',
    'HelloRetryRequest' : 'helloretryrequest',
    'HelloRetryRequestWithWrongENs' : 'helloretryrequest_with_wrong_ens',
    'ChangeCipherSpec' : 'server_ccs',
    'EncryptedExtensions' : 'en_extensions',
    'EncryptedExtensionsWithWrongENs' : 'en_extensions_with_wrong_ens',
    'CertificateRequest' : 'server_certreq',
    'CertificateRequestPostHandshake' : 'server_certreq_ph', 
    'Certificate' : 'server_cert',
    'CertificateVerify' : 'server_certver',
    'Finish' : 'server_finished', 
    'NewSessionTicket' : 'new_session_ticket',
    'NewSessionTicketWrongLifetime' : 'new_session_ticket_with_wrong_lifetime', 
    'ApplicationData' : 'server_appdata',
    'ApplicationDataPlain' : 'server_appdata_unprotected',
    'EndofEarlyData' : 'server_end_of_early',
    'NoResponse' : 'no_response',
    'unexpected_message' : 'unexpected_message',
}

class Symbol():
    def __init__(self, name=None, is_input=False) -> None:
        self.name = name
        self.is_input = is_input     
        
def tls_sut_to_ltl_map(symbol:Symbol):
    if symbol.is_input:
        symbol.name = symbol.name.replace('*', '')
        symbol.name = client_sut_to_ltl_map.get(symbol.name, 'other_inp')
    else:
        symbol.name = server_sut_to_ltl_map.get(symbol.name, 'other_out')
    return symbol 

def tls_ltl_to_sut_map(name:str):
    symbol = Symbol()
    if name in client_ltl_to_sut_map.keys():
        symbol.name = client_ltl_to_sut_map.get(symbol.name)
        symbol.is_input = True
    elif name == '\u03BC' or name == 'other_inp' or name == 'any_inp':
        symbol.name = name
        symbol.is_input = True
    else:
        symbol.name = None
        symbol.is_input = False
    return symbol 