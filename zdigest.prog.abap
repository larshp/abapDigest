REPORT zdigest.
* implemented using local classes, as this code will later be integrated into abapGit

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

ENDCLASS.

CLASS lcl_digest IMPLEMENTATION.

  METHOD run.

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
      iv_password = 'password' ).

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