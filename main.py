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
    pre_auth_indicator, saved_pre_auth_emails = (
        db_engine.pull_full_column_bigquery(
            bq_creds = st.secrets['BIGQUERY'],
            project = 'teststreamlitauth-412915',
            dataset = 'test_credentials',
            table_name = 'preauthorization_codes',
            target_col = 'email'))
    if pre_auth_indicator == 'dev_errors':
        st.error(saved_pre_auth_emails)
        pre_auth_emails = []
    elif pre_auth_indicator == 'user_errors':
        st.error("No preauthorization emails found")
        pre_auth_emails = []
    else:
        pre_auth_emails = list(saved_pre_auth_emails.values)
        st.write("pre_auth_emails", pre_auth_emails)

    if 'authenticator_usernames' not in st.session_state:
        st.session_state['authenticator_usernames'] = auth_usernames
    if 'authenticator_emails' not in st.session_state:
        st.session_state['authenticator_emails'] = auth_emails
    if 'authenticator_preauthorized' not in st.session_state:
        st.session_state['authenticator_preauthorized'] = pre_auth_emails

    ##########################################################
    # Class Instantiation
    ##########################################################
    try:
        authenticator = stauth.Authenticate(
            usernames_session_state='authenticator_usernames',
            emails_session_state='authenticator_emails',
            user_credentials_session_state='authenticator_user_credentials',
            preauthorized_session_state='authenticator_preauthorized',
            email_user='sendgrid',
            email_inputs={
                'website_name': 'SharpShares',
                'website_email': 'hello@sharpshares.com'},
            email_creds={'sendgrid_api_key':
                             st.secrets['SENDGRID']['sendgrid_api_key']},
            save_pull_function='bigquery',
            save_pull_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials'})
    except ValueError as e:
        # there are only dev errors for class instantiation and they
        # wouldn't need to show up ahead of time, just if they occur
        # during instantiation
        sterr.display_error('dev_errors', 'class_instantiation')
        st.stop()

    ##########################################################
    # Register User
    ##########################################################
    # for forms, the errors might be displayed after the form is submitted
    # and we want them above the form
    sterr.display_error('dev_errors', 'register_user')
    sterr.display_error('user_errors', 'register_user')

    # some of the arguments for bigquery methods will be the same
    all_locked_args_register_user = {
        'bq_creds': st.secrets['BIGQUERY'],
        'project': 'teststreamlitauth-412915',
        'dataset': 'test_credentials',
        'table_name': 'locked_info_register',
        'email_col': 'email',
        'locked_time_col': 'locked_time'}
    all_incorrect_attempts_args_register_user = {
        'bq_creds': st.secrets['BIGQUERY'],
        'project': 'teststreamlitauth-412915',
        'dataset': 'test_credentials',
        'table_name': 'incorrect_attempts_register',
        'email_col': 'email',
        'datetime_col': 'datetime'}

    # most of the arguments were already passed to the class instantiation
    authenticator.register_user(
        'main',
        preauthorization=True,
        email_user='sendgrid',
        email_inputs={
            'website_name': 'SharpShares',
            'website_email': 'hello@sharpshares.com'},
        email_creds={'sendgrid_api_key':
                         st.secrets['SENDGRID']['sendgrid_api_key']},
        cred_save_function='bigquery',
        cred_save_args={'table_name': 'user_credentials',
                        'bq_creds': st.secrets['BIGQUERY'],
                        'project': 'teststreamlitauth-412915',
                        'dataset': 'test_credentials'},
        auth_code_pull_function='bigquery',
        auth_code_pull_args={
            'bq_creds': st.secrets['BIGQUERY'],
            'project': 'teststreamlitauth-412915',
            'dataset': 'test_credentials',
            'table_name': 'preauthorization_codes',
            'email_col': 'email',
            'auth_code_col': 'code'},
        incorrect_attempts=4,
        locked_hours=1,
        all_locked_function='bigquery',
        all_locked_args=all_locked_args_register_user,
        all_incorrect_attempts_function='bigquery',
        all_incorrect_attempts_args=all_incorrect_attempts_args_register_user)

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

    ##########################################################
    # Login
    ##########################################################
    st.write('---')

    if not authenticator.check_authentication_status():
        sterr.display_error('dev_errors', 'login')
        sterr.display_error('user_errors', 'login')

        # some of the arguments for bigquery methods will be the same
        all_locked_args_login = {
            'bq_creds': st.secrets['BIGQUERY'],
            'project': 'teststreamlitauth-412915',
            'dataset': 'test_credentials',
            'table_name': 'locked_info',
            'username_col': 'username',
            'locked_time_col': 'locked_time',
            'unlocked_time_col': 'unlocked_time'}
        all_incorrect_attempts_args_login = {
            'bq_creds': st.secrets['BIGQUERY'],
            'project': 'teststreamlitauth-412915',
            'dataset': 'test_credentials',
            'table_name': 'incorrect_attempts',
            'username_col': 'username',
            'datetime_col': 'datetime'}

        authenticator.login(
            location='main',
            password_pull_function='bigquery',
            password_pull_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials',
                'table_name': 'user_credentials',
                'username_col': 'username',
                'password_col': 'password'},
            incorrect_attempts=4,
            locked_hours=1,
            all_locked_function='bigquery',
            all_locked_args=all_locked_args_login,
            all_incorrect_attempts_function='bigquery',
            all_incorrect_attempts_args=all_incorrect_attempts_args_login)

        sterr.display_error('dev_errors', 'login', False)
        sterr.display_error('user_errors', 'login', False)

        ##########################################################
        # Forgot Username
        ##########################################################

        sterr.display_error('dev_errors', 'forgot_username')
        sterr.display_error('user_errors', 'forgot_username')

        authenticator.forgot_username(
            location='main',
            username_pull_function='bigquery',
            username_pull_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials',
                'table_name': 'user_credentials',
                'email_col': 'email',
                'username_col': 'username'},
            email_user='sendgrid',
            email_inputs={
                'website_name': 'SharpShares',
                'website_email': 'hello@sharpshares.com'},
            email_creds={'sendgrid_api_key':
                             st.secrets['SENDGRID']['sendgrid_api_key']})

        sterr.display_error('dev_errors', 'forgot_username', False)
        sterr.display_error('user_errors', 'forgot_username', False)

        ##########################################################
        # Forgot Password
        ##########################################################

        sterr.display_error('dev_errors', 'forgot_password')
        sterr.display_error('user_errors', 'forgot_password')

        authenticator.forgot_password(
            location='main',
            username_pull_function='bigquery',
            username_pull_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials',
                'table_name': 'user_credentials',
                'email_col': 'email',
                'username_col': 'username'},
            password_store_function='bigquery',
            password_store_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials',
                'table_name': 'user_credentials',
                'username_col': 'username',
                'password_col': 'password',
                'datetime_col': 'datetime'},
            email_user='sendgrid',
            email_inputs={
                'website_name': 'SharpShares',
                'website_email': 'hello@sharpshares.com'},
            email_creds={'sendgrid_api_key':
                             st.secrets['SENDGRID']['sendgrid_api_key']})

        sterr.display_error('dev_errors', 'forgot_password', False)
        sterr.display_error('user_errors', 'forgot_password', False)

    else:

        ##########################################################
        # Update User Info
        ##########################################################

        sterr.display_error('dev_errors', 'update_user_info')
        sterr.display_error('user_errors', 'update_user_info')

        authenticator.update_user_info(
            location='main',
            info_pull_function='bigquery',
            info_pull_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials',
                'table_name': 'user_credentials',
                'col_map': {'email': 'email',
                            'username': 'username',
                            'password': 'password'}},
            info_store_function='bigquery',
            info_store_args={
                'bq_creds': st.secrets['BIGQUERY'],
                'project': 'teststreamlitauth-412915',
                'dataset': 'test_credentials',
                'table_name': 'user_credentials',
                'col_map': {'email': 'email',
                            'username': 'username',
                            'password': 'password',
                            'datetime': 'datetime'}},
            email_user='sendgrid',
            email_inputs={
                'website_name': 'SharpShares',
                'website_email': 'hello@sharpshares.com'},
            email_creds={'sendgrid_api_key':
                             st.secrets['SENDGRID']['sendgrid_api_key']},
            store_new_info='email')

        sterr.display_error('dev_errors', 'update_user_info', False)
        sterr.display_error('user_errors', 'update_user_info', False)

        ##########################################################
        # Logout
        ##########################################################

        authenticator.logout()

    ##########################################################
    # Create Preauthorization Codes
    ##########################################################
    st.write('---')

    st.button('Create Preauth Codes', on_click=create_preauth_codes)


    if ('stauth' in st.session_state and 'authentication_status' in
            st.session_state.stauth.keys()):
        st.write('authentication_status',
                 st.session_state.stauth['authentication_status'])
    if ('stauth' in st.session_state and 'username' in
            st.session_state.stauth.keys()):
        st.write('username', st.session_state.stauth['username'])
    if ('stauth' in st.session_state and 'failed_login_attempts' in
            st.session_state.stauth.keys()):
        st.write('failed_login_attempts',
                 st.session_state.stauth['failed_login_attempts'])
    if ('stauth' in st.session_state and 'login_unlock' in
            st.session_state.stauth.keys()):
        st.write('login_unlock', st.session_state.stauth['login_unlock'])
    if ('stauth' in st.session_state and 'login_lock' in
            st.session_state.stauth.keys()):
        st.write('login_lock', st.session_state.stauth['login_lock'])
    if ('stauth' in st.session_state and 'new_email' in
            st.session_state.stauth.keys()):
        st.write('new_email', st.session_state.stauth['new_email'])
    if ('stauth' in st.session_state and 'new_username' in
            st.session_state.stauth.keys()):
        st.write('new_username', st.session_state.stauth['new_username'])
    if ('stauth' in st.session_state and 'new_password' in
            st.session_state.stauth.keys()):
        st.write('new_password', st.session_state.stauth['new_password'])


def create_preauth_codes():
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
