import streamlit as st

import StreamlitAuth as stauth


def main():
    verifier = stauth.Verification()
    try:
        verifier.verify_email(
            email_code_pull_function='bigquery',
            email_code_pull_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials',
                'table_name': 'user_credentials',
                'email_col': 'email',
                'email_code_col': 'email_code'},
            verified_store_function='bigquery',
            verified_store_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials',
                'table_name': 'user_credentials',
                'email_col': 'email',
                'verified_col': 'email_verified',
                'datetime_col': 'datetime'})
    # let the user know if there's a key error and they don't have the
    # correct URL parameters
    except KeyError as ke:
        st.error("The expected email and authorization code are not "
                 "present. Please make sure you use the link from "
                 "the email you were sent.")
    except Exception as e:
        st.error(e)

    if ('stauth' in st.session_state and 'email_verified' in
            st.session_state.stauth and st.session_state.stauth[
                'email_verified']):
        st.success("Email Verified!\n\n"
                   "You can now login and use the website.")
    elif ('stauth' in st.session_state and 'email_verified' in
            st.session_state.stauth and not st.session_state.stauth[
                'email_verified']):
        st.error("Email Code incorrect, please try again or contact your "
                 "administrator.")


if __name__ == '__page__':
    main()
