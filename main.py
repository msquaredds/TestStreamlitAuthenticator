"""
Used to test all the functions of the StreamlitAuth package starting from
version 0.4.0 / 09_17_2024 (and archived version was used for all tests
prior to that).
"""

import streamlit as st

import StreamlitAuth as stauth
from StreamlitAuth import ErrorHandling as sterr


def main():
    ##########################################################
    # Get Stored Data
    ##########################################################
    # get the stored usernames and emails
    db_engine = stauth.BQTools()
    usernames_indicator, saved_auth_usernames = (
        db_engine.pull_full_column_bigquery(
            bq_creds = st.secrets['BIGQUERY'],
            project = 'teststreamlitauth-412915',
            dataset = 'test_credentials',
            table_name = 'user_credentials',
            target_col = 'username'))
    if usernames_indicator == 'dev_errors':
        st.error(saved_auth_usernames)
        auth_usernames = []
    elif usernames_indicator == 'user_errors':
        st.error("No usernames found")
        auth_usernames = []
    else:
        auth_usernames = list(saved_auth_usernames.values)
        st.write("auth_usernames", auth_usernames)
    emails_indicator, saved_auth_emails = (
        db_engine.pull_full_column_bigquery(
            bq_creds = st.secrets['BIGQUERY'],
            project = 'teststreamlitauth-412915',
            dataset = 'test_credentials',
            table_name = 'user_credentials',
            target_col = 'email'))
    if emails_indicator == 'dev_errors':
        st.error(saved_auth_emails)
        auth_emails = []
    elif emails_indicator == 'user_errors':
        st.error("No emails found")
        auth_emails = []
    else:
        auth_emails = list(saved_auth_emails.values)
        st.write("auth_emails", auth_emails)

    if 'authenticator_usernames' not in st.session_state:
        st.session_state['authenticator_usernames'] = auth_usernames
    if 'authenticator_emails' not in st.session_state:
        st.session_state['authenticator_emails'] = auth_emails
    if 'authenticator_preauthorized' not in st.session_state:
        st.session_state['authenticator_preauthorized'] = None

    ##########################################################
    # Class Instantiation
    ##########################################################
    authenticator = stauth.Authenticate(
        usernames_session_state='authenticator_usernames',
        emails_session_state='authenticator_emails',
        user_credentials_session_state='authenticator_user_credentials',
        preauthorized_session_state=None,
        email_user='sendgrid',
        email_inputs={
            'website_name': 'SharpShares',
            'website_email': 'hello@sharpshares.com'},
        email_creds={'sendgrid_api_key':
                         st.secrets['SENDGRID']['sendgrid_api_key']},
        save_pull_function='hi',
        save_pull_args={
            'bq_creds': st.secrets['BIGQUERY'],
            'project': 'teststreamlitauth-412915',
            'dataset': 'test_credentials'})

    # there are only dev errors for class instantiation and they wouldn't
    # need to show up ahead of time, just if they occur during
    # instantiation
    sterr.display_error('dev_errors', 'class_instantiation')

    ##########################################################
    # Register User
    ##########################################################
    # for forms, the errors might be displayed after the form is submitted
    # and we want them above the form
    sterr.display_error('dev_errors', 'register_user')
    sterr.display_error('user_errors', 'register_user')

    # most of the arguments were already passed to the class instantiation
    authenticator.register_user(
        'main',
        cred_save_args={'table_name': 'user_credentials'})

    sterr.display_error('dev_errors', 'register_user', False)
    sterr.display_error('user_errors', 'register_user', False)

    # here we display any session_state info, outside of errors, that may
    # have been updated in register_user
    if 'authenticator_usernames' in st.session_state:
        st.write('authenticator_usernames',
                 st.session_state['authenticator_usernames'])
    if 'authenticator_emails' in st.session_state:
        st.write('authenticator_emails',
                 st.session_state['authenticator_emails'])
    if 'authenticator_preauthorized' in st.session_state:
        st.write('authenticator_preauthorized',
                 st.session_state['authenticator_preauthorized'])
    if 'authenticator_user_credentials' in st.session_state:
        st.write('authenticator_user_credentials',
                 st.session_state['authenticator_user_credentials'])


if __name__ == '__main__':
    main()
