REPORT zdigest.
* implemented using local classes, as this code will later be integrated into abapGit

*CALL FUNCTION 'GENERAL_GET_RANDOM_STRING'
*  EXPORTING
*    NUMBER_CHARS  = 24
*  IMPORTING
*    RANDOM_STRING = lv_snonce.
*
*CALL METHOD cl_http_utility=>ENCODE_BASE64
*  EXPORTING
*    UNENCODED = lv_snonce
*  RECEIVING
*    ENCODED   = lv_b64nonce.

INCLUDE zabapgit_definitions.
INCLUDE zabapgit_html.
INCLUDE zabapgit_exceptions.
INCLUDE zabapgit_util.

CLASS lcl_digest DEFINITION.

  PUBLIC SECTION.
    CLASS-METHODS:
      run
        IMPORTING
          iv_qop      TYPE string
          iv_realm    TYPE string
          iv_nonce    TYPE string
          iv_username TYPE string
          iv_uri      TYPE string
          iv_method   TYPE string
          iv_cnonse   TYPE string " todo
          iv_password TYPE string
        RETURNING
          VALUE(rv_response) TYPE string.

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

    DATA: lv_str TYPE string.


    CONCATENATE iv_username ':' iv_realm ':' iv_password INTO lv_str.
    DATA(lv_ha1) = md5( lv_str ).

    CONCATENATE iv_method ':' iv_uri INTO lv_str.
    DATA(lv_ha2) = md5( lv_str ).

* todo, nc = 00000001
    CONCATENATE lv_ha1 ':' iv_nonce ':00000001:' iv_cnonse ':' iv_qop ':' lv_ha2 INTO lv_str.
    rv_response = md5( lv_str ).

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
      test02 FOR TESTING.

ENDCLASS.

CLASS ltcl_digest IMPLEMENTATION.

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