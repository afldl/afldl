IKEv2_formulas = {
    # 1.In all cases, all IKE_SA_INIT exchanges MUST complete before any other exchange type, 
    # then all IKE_AUTH exchanges MUST complete, and following that, any number of
    # CREATE_CHILD_SA and INFORMATIONAL exchanges may occur in any order.
    'formula_1' : '(init_req & (X init_resp)) R !(other_req & (X (!no_response & !wrong_init_resp)))',
    'formula_2' : '((init_req & (X init_resp)) R !(auth_req & (X auth_resp))) & ((auth_req & (X auth_resp)) R !(create_child_req & (X create_child_resp)))',
    # 2.Mandatory The response with the authentication payload is received only after the request with the correct authentication payload has been sent.
    'formula_3' : '(init_req & (X init_resp)) -> WX G(! auth_req -> WX ! auth_resp)',
    # 3.After successful authentication, IKE cannot be re-initialized on the current IKE channel
    'formula_4' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G(!(init_req & X init_resp))',
    # 4.The effect of a successful authentication can be continued, and can't again
    'formula_5' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> XXX G(!(auth_req & X auth_resp))',
    # 5.All messages following the initial exchange are cryptographically protected using the cryptographic algorithms and keys negotiated in
    # the IKE_SA_INIT exchange. All subsequent messages include an Encrypted payload, even if they are referred to
    # in the text as "empty".
    'formula_6' : '(init_req & (X init_resp)) -> WX G(! ((other_req | init_req) & X plain_resp))',
    # 6.Except when using this option to negotiate transport mode, all Child SAs will use tunnel mode.
    'formula_7' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G(! create_child_transmode_req -> WX ! create_child_transmode_resp)',
    # 10.ESP and AH SAs always exist in pairs, with one SA in each direction.
    # When an SA is closed, both members of the pair MUST be closed (that is, deleted).
    'formula_8' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G(!(ipsec_req & X ipsec_mismatch_resp) & !(old_ipsec_req & X ipsec_mismatch_resp))',
    # 11.Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it. The response to a request
    # that deletes the IKE SA is an empty INFORMATIONAL response.
    'formula_9' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G (!(del_ike_req & X ! del_ike_resp))',
    # 7.The recipient of an INFORMATIONAL exchange request MUST send some response;
    'formula_10' : '(init_req & (X init_resp)) -> WX G(!(info_null_req & X (other_req | init_req)))',
    # 15.The main reason for rekeying the IKE SA is to ensure that the
    # compromise of old keying material does not provide information about
    # the current keys, or vice versa. Therefore, implementations MUST
    # perform a new Diffie-Hellman exchange when rekeying the IKE SA. In
    # other words, an initiator MUST NOT propose the value "NONE" for the
    # Diffie-Hellman transform, and a responder MUST NOT accept such a proposal.
    'formula_11' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G(!(rekey_no_ke_req & X (rekey_no_ke_resp | rekey_ike_resp)))',
    # Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it.
    'formula_12' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G((del_ike_req & X del_ike_resp) -> WX G !(ipsec_req & X ipsec_resp))',
    'formula_13' : '((init_req & (X init_resp)) & XX ((auth_req & (X auth_resp)) & XX (rekey_ike_req & (X rekey_ike_resp)))) -> WX G((old_del_ike_req & X del_ike_resp) -> WX G !(old_ipsec_req & X ipsec_resp))',
    'formula_14' : '((init_req & (X init_resp)) & XX ((auth_req & (X auth_resp)) & XX (rekey_child_sa_req & (X create_child_resp)))) -> WX G !(old_ipsec_req & X ipsec_resp)',
    'formula_15' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G(ipsec_req -> X ipsec_resp)',
    'formula_16' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G(rekey_child_sa_req -> X create_child_resp)',
    # A failed attempt to create a Child SA SHOULD NOT tear down the IKE SA: there is no reason to lose the work done to set up the IKE SA.
    'formula_17' : '((init_req & (X init_resp)) & XX (auth_req & (X auth_resp))) -> WX G!(create_child_req & X del_ike_resp)',
    # 7.Once a peer receives a request to rekey an IKE SA or sends a request to rekey an IKE SA, it SHOULD NOT start any
    # new CREATE_CHILD_SA exchanges on the IKE SA that is being rekeyed.
    'formula_18' : '((init_req & (X init_resp)) & XX ((auth_req & (X auth_resp)) & XX (rekey_ike_req & (X rekey_ike_resp)))) -> WX G((old_del_ike_req & X del_ike_resp) -> WX G !(old_create_child_req & X create_child_resp))',
}

IKEv1_formulas = {
    # An initiator MAY provide multiple proposals for negotiation; a responder MUST reply with only one.
    # 'formula_1' : 'G!((main_mode_1_req | multi_sa_main_mode_1_req)& X multi_sa_main_mode_1_resp)',
    # The SA payload MUST precede all other payloads in a phase 1 exchange.
    # 'formula_2' : '((main_mode_1_req & X main_mode_1_resp) R !(main_mode_2_req & X main_mode_2_resp))',
    'formula_3' : '(((main_mode_1_req & (X main_mode_1_resp)) & XX (main_mode_2_req & (X main_mode_2_resp))) R !(main_mode_3_req & X main_mode_3_resp))',
    # "New Group Mode" MUST ONLY be used after phase 1.
    'formula_4' : '((main_mode_3_req & X main_mode_3_resp) R !(new_group_req & X new_group_resp))',
    # "Main Mode" for phase 1 provides identity protection.
    'formula_5' : '((main_mode_1_req & (X main_mode_1_resp)) & XX (main_mode_2_req & (X main_mode_2_resp))) -> WX G!(main_mode_3_req & X plain_main_mode_3_resp)',
    # Implementations MUST NOT switch exchange types in the middle of an exchange.
    'formula_6' : '((main_mode_1_req & (X main_mode_1_resp)) -> WX G !(aggressive_mode_1_req & X aggressive_mode_1_resp)) & ((aggressive_mode_1_req & (X aggressive_mode_1_resp)) -> WX G !(main_mode_1_req & X main_mode_1_resp))',
    'formula_7' : '(main_mode_1_req & X main_mode_1_resp) -> WX G !((aggressive_mode_1_req & X aggressive_mode_1_resp) & F(main_mode_3_req & X main_mode_3_resp))',
    # The length of nonce payload MUST be between 8 and 256 bytes inclusive.
    'formula_8' : '(main_mode_1_req & (X main_mode_1_resp)) -> WX G!(wrong_nonce_main_mode_2_req & X main_mode_2_resp)',
    # To put it another way, for phase 1 exchanges there MUST NOT be multiple Proposal Payloads for a single SA payload and there MUST NOT be multiple SA payloads.
    'formula_9' : 'G!(wrong_sa_main_mode_1_req & X main_mode_1_resp)',
    # In Quick Mode, a HASH payload MUST immediately follow the ISAKMP header and a SA payload MUST immediately follow the HASH.
    'formula_10' : '((main_mode_1_req & (X main_mode_1_resp)) & XX ((main_mode_2_req & (X main_mode_2_resp)) & XX (main_mode_3_req & (X main_mode_3_resp)))) -> WX G(wrong_order_quick_mode_1_req -> X quick_mode_1_resp)',
    # authentication
    'formula_11' : '((main_mode_1_req & (X main_mode_1_resp)) & XX (main_mode_2_req & (X main_mode_2_resp))) -> WX G(! main_mode_3_req -> WX ! main_mode_3_resp)',
    # test ipsec 
    'formula_12' : '((main_mode_1_req & (X main_mode_1_resp)) & XX ( (main_mode_2_req & (X main_mode_2_resp)) & XX (((main_mode_3_req & (X main_mode_3_resp)) & XX ((quick_mode_1_req & (X quick_mode_1_resp)) & XX (quick_mode_2_req)))))) -> WX G((delete_ike_req & X delete_ike_resp) -> WX G !(test_tunnel_esp_req & X esp_reply_resp))',
    'formula_13' : '((quick_mode_1_req & (X quick_mode_1_resp)) & XX quick_mode_2_req) R !(test_tunnel_esp_req & X esp_reply_resp)',
    'formula_14' : '((main_mode_1_req & (X main_mode_1_resp)) & XX ( (main_mode_2_req & (X main_mode_2_resp)) & XX (((main_mode_3_req & (X main_mode_3_resp)) & XX ((quick_mode_1_req & (X quick_mode_1_resp)) & XX (quick_mode_2_req)))))) -> WX G(!(test_tunnel_esp_req & X ipsec_mismatch_resp))',
}

events_map = {
    'init_req' : 'SAINIT_SA-KE-NONCE',
    'auth_req' : 'AUTH_IDi-AUTH-SA-TSi-TSr',
    'create_child_req' : 'CHILDSA_SA-NONCE-TSi-TSr',
    'transmode_req' : 'CHILDSA_TransMode-SA-NONCE-TSi-TSr',
    'del_ike_req' : 'INFO_DelIKE',
    'old_del_ike_req' : 'OI_INFO_DelIKE',
    'old_create_child_req' : 'OI_CHILDSA_SA-NONCE-TSi-TSr',
    'info_null_req' : 'INFO_',
    'rekey_ike_req' : 'CHILDSA_RekeyIKE-KE-NONCE',
    'rekey_no_ke_req' : 'CHILDSA_RekeyIKE-NONCE',
    'ipsec_req' : 'test_ipsec',
    'old_ipsec_req' : 'test_old_ipsec',
    'rekey_child_sa_req': 'CHILDSA_RekeySA-SA-NONCE-TSi-TSr',
    
    'main_mode_1_req' : 'main_mode_1',
    'main_mode_2_req' : 'main_mode_2',
    'main_mode_3_req' : 'main_mode_3',
    'quick_mode_1_req' : 'quick_mode_1',
    'quick_mode_2_req' : 'quick_mode_2',
    'aggressive_mode_1_req' : 'aggressive_mode_1',
    'aggressive_mode_2_req' : 'aggressive_mode_2',
    'new_group_req' : 'new_group',
    'test_tunnel_esp_req' : 'test_tunnel_ESP',
    'delete_ike_req' : 'delete_IKE',
    'wrong_nonce_main_mode_2_req' : 'wrong_nonce_main_mode_2',
    'multi_sa_main_mode_1_req' : 'multi_sa_main_mode_1',
    'wrong_order_quick_mode_1_req' : 'wrong_order_quick_mode_1'
}

def abstract_symbol_to_more_abstract_symbol_v1(symbol:str, is_request:bool):
    if symbol == 'No_response':
        result = None
    input_alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_1',  'quick_mode_2', 'test_tunnel_esp', 'delete_esp', 'delete_ike', 'aggressive_mode_1', 'aggressive_mode_2', 'new_group', 'multi_sa_main_mode_1', 'wrong_nonce_main_mode_2', 'wrong_order_quick_mode_1']
    output_alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_1', 'esp_reply', 'wrong_esp_reply', 'delete_esp', 'delete_ike', 'aggressive_mode_1', 'multi_sa_main_mode_1', 'plain_main_mode_3']
    symbol = symbol.lower()
    symbol = symbol.replace('*', '')
    if is_request:
        result = f'{symbol}_req' if symbol in input_alphabet else 'other_req'
    else:
        tokens = symbol.split('-')
        result = ''
        for t in tokens:
            result += f'{t}_resp-' if t in output_alphabet else 'other_resp-'
        result = result.strip('-')
    return result
    
def abstract_symbol_to_more_abstract_symbol_v2(symbol:str, is_request:bool):
    result = None
    others = ['DecryptedError', 'PortUnreachable']
    if symbol == 'No_response':
        return 'no_response'
    elif symbol in others:
        result = symbol
    elif symbol == 'Plain_response':
        result = 'plain_resp'
    elif 'test_ipsec' in symbol:
        return 'ipsec_req'
    elif 'test_old_ipsec' in symbol:
        return 'old_ipsec_req'
    elif 'Replay' in symbol:
        result = 'ipsec_resp' if 'misMatch' not in symbol else 'ipsec_mismatch_resp'
        return result
    else:
        result = ''
        # print(symbol)
        if 'OI_' in symbol:
            result += 'old_'
            symbol = symbol.split('OI_')[1]
        # print(symbol)
        ex_type = symbol.split('_')[0]
        pds = symbol.split('_')[1]
        if ex_type == 'SAINIT':
            if 'SA' in pds and 'KE' in pds and 'NONCE' in pds:
                result += 'init'
            else:
                result += 'wrong_init'
        elif ex_type == 'AUTH':
            if 'AUTH*' in pds:
                result += 'wrong_auth'
            elif 'AUTH' in pds:
                result += 'auth'
            elif '18' in pds:
                result += 'auth_fail'
        elif ex_type == 'CHILDSA':
            if 'RekeyIKE' in pds:
                if 'KE' in pds and 'NONCE' in pds:
                    result += 'rekey_ike'
                else:
                    result += 'wrong_rekey_ike'
            elif 'RekeySA' in pds:
                result += 'rekey_child_sa'
            elif 'SA' in pds and 'NONCE' in pds:
                result += 'create_child' if 'TransMode' not in pds else 'create_child_transmode'
        elif ex_type == 'INFO':
            if 'DelIKE' in pds:
                result += 'del_ike'
            elif 'DelChild' in pds or 'DELETE' in pds:
                result += 'del_child'
        if result is None:
            result = 'other'
        else:
            result += '_req' if is_request else '_resp'
    return result

def abstract(symbol:str, is_request:bool, version):
    if version == 'v1':
        return abstract_symbol_to_more_abstract_symbol_v1(symbol, is_request)
    elif version == 'v2':
        return abstract_symbol_to_more_abstract_symbol_v2(symbol, is_request)