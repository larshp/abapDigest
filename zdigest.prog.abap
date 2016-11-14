REPORT zdigest.
* implemented using local classes, as this code will later be integrated into abapGit

PARAMETERS: p_url  TYPE text200 OBLIGATORY,
            p_user TYPE text20 OBLIGATORY DEFAULT 'admin',
            p_pass TYPE text20 OBLIGATORY DEFAULT 'secret'.

INCLUDE zabapgit_definitions.
INCLUDE zabapgit_html.
INCLUDE zabapgit_exceptions.
INCLUDE zabapgit_util.

START-OF-SELECTION.
  PERFORM run.

CLASS lcl_digest DEFINITION.

  PUBLIC SECTION.
    CLASS-METHODS:
      run
        IMPORTING
          iv_qop             TYPE string
          iv_realm           TYPE string
          iv_nonce           TYPE string
          iv_username        TYPE clike
          iv_uri             TYPE string
          iv_method          TYPE string
          iv_cnonse          TYPE string " todo
          iv_password        TYPE clike
        RETURNING
          VALUE(rv_response) TYPE string,
      parse
        IMPORTING
          iv_value  TYPE string
        EXPORTING
          ev_scheme TYPE string
          ev_realm  TYPE string
          ev_qop    TYPE string
          ev_nonce  TYPE string.

  PRIVATE SECTION.
    CLASS-METHODS:
      md5
        IMPORTING
          iv_data        TYPE string
        RETURNING
          VALUE(rv_hash) TYPE string.

ENDCLASS.

CLASS lcl_digest IMPLEMENTATION.

  METHOD run.

    DATA(lv_ha1) = md5( |{ iv_username }:{ iv_realm }:{ iv_password }| ).
    DATA(lv_ha2) = md5( |{ iv_method }:{ iv_uri }| ).
* todo, nc = 00000001
    rv_response = md5( |{ lv_ha1 }:{ iv_nonce }:00000001:{ iv_cnonse }:{ iv_qop }:{ lv_ha2 }| ).

  ENDMETHOD.

  METHOD parse.

    CLEAR: ev_scheme,
           ev_realm,
           ev_qop,
           ev_nonce.

    FIND REGEX '^(\w+)' IN iv_value SUBMATCHES ev_scheme.
    FIND REGEX 'realm="([\w ]+)"' IN iv_value SUBMATCHES ev_realm.
    FIND REGEX 'qop="(\w+)"' IN iv_value SUBMATCHES ev_qop.
    FIND REGEX 'nonce="([\w=/+\$]+)"' IN iv_value SUBMATCHES ev_nonce.

  ENDMETHOD.

  METHOD md5.

    DATA: lv_xstr TYPE xstring,
          lv_hash TYPE xstring.


    lv_xstr = lcl_convert=>string_to_xstring_utf8( iv_data ).

    CALL FUNCTION 'CALCULATE_HASH_FOR_RAW'
      EXPORTING
        alg            = 'MD5'
        data           = lv_xstr
      IMPORTING
        hashxstring    = lv_hash
      EXCEPTIONS
        unknown_alg    = 1
        param_error    = 2
        internal_error = 3
        OTHERS         = 4.
    IF sy-subrc <> 0.
      BREAK-POINT.
    ENDIF.

    rv_hash = lv_hash.
    TRANSLATE rv_hash TO LOWER CASE.

  ENDMETHOD.

ENDCLASS.

CLASS ltcl_digest DEFINITION FOR TESTING RISK LEVEL HARMLESS DURATION SHORT FINAL.

  PRIVATE SECTION.
    METHODS:
      test01 FOR TESTING,
      test02 FOR TESTING,
      parse01 FOR TESTING,
      parse02 FOR TESTING.

ENDCLASS.

CLASS ltcl_digest IMPLEMENTATION.

  METHOD parse01.

    DATA: lv_value  TYPE string,
          lv_scheme TYPE string,
          lv_realm  TYPE string,
          lv_qop    TYPE string,
          lv_nonce  TYPE string.


    lv_value = 'Digest realm="Gerrit Code Review", domain="http://localhost:8080/", qop="auth", nonce="ypsTDNs64ov28b6EPoejnpxd46Gdx8he5TS1oA==$"'.

    lcl_digest=>parse(
      EXPORTING
        iv_value  = lv_value
      IMPORTING
        ev_scheme = lv_scheme
        ev_realm  = lv_realm
        ev_qop    = lv_qop
        ev_nonce  = lv_nonce ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_scheme
      exp = 'Digest' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_realm
      exp = 'Gerrit Code Review' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_qop
      exp = 'auth' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_nonce
      exp = 'ypsTDNs64ov28b6EPoejnpxd46Gdx8he5TS1oA==$' ).

  ENDMETHOD.

  METHOD parse02.

    DATA: lv_value  TYPE string,
          lv_scheme TYPE string,
          lv_realm  TYPE string,
          lv_qop    TYPE string,
          lv_nonce  TYPE string.


    lv_value = 'Basic realm="User Visible Realm"'.

    lcl_digest=>parse(
      EXPORTING
        iv_value  = lv_value
      IMPORTING
        ev_scheme = lv_scheme
        ev_realm  = lv_realm
        ev_qop    = lv_qop
        ev_nonce  = lv_nonce ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_scheme
      exp = 'Basic' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_realm
      exp = 'User Visible Realm' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_qop
      exp = '' ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_nonce
      exp = '' ).

  ENDMETHOD.

  METHOD test01.

    DATA: lv_response TYPE string.


    lv_response = lcl_digest=>run(
      iv_qop      = 'auth'
      iv_realm    = 'Gerrit Code Review'
      iv_nonce    = '1vLNacdTq1FWk2ac6PTHC8RiB1Pz7DcWAY0YfQ==$'
      iv_username = 'admin'
      iv_uri      = '/new_project/info/refs?service=git-receive-pack'
      iv_method   = 'GET'
      iv_cnonse   = 'ZmU2YjcwOWFlZGNkYjk5NDAwMDgwMmQwMDAwN2IzMzc='
      iv_password = 'secret' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_response
      exp = '87fbab11a72cf0900ec3ea2c0a597850' ).

  ENDMETHOD.

  METHOD test02.
* https://en.wikipedia.org/wiki/Digest_access_authentication

    DATA: lv_response TYPE string.


    lv_response = lcl_digest=>run(
      iv_qop      = 'auth'
      iv_realm    = 'testrealm@host.com'
      iv_nonce    = 'dcd98b7102dd2f0e8b11d0f600bfb0c093'
      iv_username = 'Mufasa'
      iv_uri      = '/dir/index.html'
      iv_method   = 'GET'
      iv_cnonse   = '0a4f113b'
      iv_password = 'Circle Of Life' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_response
      exp = '6629fae49393a05397450978507c4ef1' ).

  ENDMETHOD.

ENDCLASS.

FORM run.

  DATA: lt_fields   TYPE tihttpnvp,
        lv_value    TYPE string,
        li_client   TYPE REF TO if_http_client,
        lv_scheme   TYPE string,
        lv_realm    TYPE string,
        lv_response TYPE string,
        lv_method   TYPE string,
        lv_uri      TYPE string,
        lv_auth     TYPE string,
        lv_cnonce   TYPE string,
        lv_qop      TYPE string,
        lv_nonce    TYPE string.


  cl_http_client=>create_by_url(
    EXPORTING
      url    = CONV #( p_url )
      ssl_id = 'ANONYM'
    IMPORTING
      client = li_client ).

  li_client->propertytype_logon_popup = if_http_client=>co_disabled.

  PERFORM send_receive USING li_client.

  li_client->response->get_header_fields(
    CHANGING fields = lt_fields ).

  lv_value = li_client->response->get_header_field( 'www-authenticate' ).

  lcl_digest=>parse(
    EXPORTING
      iv_value  = lv_value
    IMPORTING
      ev_scheme = lv_scheme
      ev_realm  = lv_realm
      ev_qop    = lv_qop
      ev_nonce  = lv_nonce ).

  ASSERT NOT lv_nonce IS INITIAL.

  lv_method = 'GET'.
  lv_uri = li_client->request->get_header_field( '~request_uri' ).

  CALL FUNCTION 'GENERAL_GET_RANDOM_STRING'
    EXPORTING
      number_chars  = 24
    IMPORTING
      random_string = lv_cnonce.

  lv_response = lcl_digest=>run(
    iv_qop      = lv_qop
    iv_realm    = lv_realm
    iv_nonce    = lv_nonce
    iv_username = p_user
    iv_uri      = lv_uri
    iv_method   = lv_method
    iv_cnonse   = lv_cnonce
    iv_password = p_pass ).

* client response
  lv_auth = |Digest username="{ p_user
    }", realm="{ lv_realm
    }", nonce="{ lv_nonce
    }", uri="{ lv_uri
    }", qop={ lv_qop
    }, nc=00000001, cnonce="{ lv_cnonce
    }", response="{ lv_response }"|.

  li_client->request->set_header_field(
    name  = 'Authorization'
    value = lv_auth ).

  PERFORM send_receive USING li_client.

ENDFORM.

FORM send_receive USING pi_client TYPE REF TO if_http_client.

  DATA: lv_code TYPE i.


  pi_client->send( ).
  pi_client->receive(
    EXCEPTIONS
      http_communication_failure = 1
      http_invalid_state         = 2
      http_processing_failed     = 3
      OTHERS                     = 4 ).
  WRITE: / sy-subrc.
  pi_client->response->get_status(
    IMPORTING
      code   = lv_code ).
  WRITE: / lv_code.

ENDFORM.