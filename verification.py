import streamlit as st

import StreamlitAuth as stauth


def main():
    verifier = stauth.Verification()
    verifier.preauthorization_code(
        email=["amelesko@gmail.com",
               "alex.melesko@msquaredds.com"],
        code_store_function='bigquery',
        code_store_args={
            'bq_creds': st.secrets['BIGQUERY'],
            'project': 'teststreamlitauth-412915',
            'dataset': 'test_credentials',
            'table_name': 'preauthorization_codes',
            'email_col': 'email',
            'code_col': 'code'},
        email_user='sendgrid',
        email_inputs={
            'website_name': 'SharpShares',
            'website_email': 'hello@sharpshares.com'},
        email_creds={'sendgrid_api_key':
                         st.secrets['SENDGRID']['sendgrid_api_key']}
    )


if __name__ == '__main__':
    main()
