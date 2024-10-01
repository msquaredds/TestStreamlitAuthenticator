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
    try:
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
                             st.secrets['SENDGRID']['sendgrid_api_key']},)
            # save_pull_function='bigquery',
            # save_pull_args={
            #     'bq_creds': st.secrets['BIGQUERY'],
            #     'project': 'teststreamlitauth-412915',
            #     'dataset': 'test_credentials'})
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

    # most of the arguments were already passed to the class instantiation
    authenticator.register_user(
        'main',
        cred_save_function='bigquery',
        cred_save_args={'table_name': 'user_credentials',
                        'bq_creds': st.secrets['BIGQUERY'],
                        'project': 'teststreamlitauth-412915',
                        'dataset': 'test_credentials',
                        })

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

    sterr.display_error('dev_errors', 'login')
    sterr.display_error('user_errors', 'login')

    if not authenticator.check_authentication_status():
        # some of the arguments for bigquery methods will be the same
        all_locked_args = {
            'bq_creds': st.secrets['BIGQUERY'],
            'project': 'teststreamlitauth-412915',
            'dataset': 'test_credentials',
            'table_name': 'locked_info',
            'username_col': 'username',
            'locked_time_col': 'locked_time',
            'unlocked_time_col': 'unlocked_time'}
        all_incorrect_attempts_args = {
            'bq_creds': st.secrets['BIGQUERY'],
            'project': 'teststreamlitauth-412915',
            'dataset': 'test_credentials',
            'table_name': 'incorrect_attempts',
            'username_col': 'username',
            'datetime_col': 'datetime'}

        st.write("test5")

        authenticator.login(location='main',
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
                            # all_locked_function='bigquery',
                            # all_locked_args=all_locked_args,
                            locked_info_function='bigquery',
                            locked_info_args=all_locked_args,
                            # store_locked_time_function='bigquery',
                            # store_locked_time_args=all_locked_args,
                            # store_unlocked_time_function='bigquery',
                            # store_unlocked_time_args=all_locked_args,
                            all_incorrect_attempts_function='bigquery',
                            all_incorrect_attempts_args=all_incorrect_attempts_args,
                            # store_incorrect_attempts_function='bigquery',
                            # store_incorrect_attempts_args=all_incorrect_attempts_args,
                            # pull_incorrect_attempts_function='bigquery',
                            # pull_incorrect_attempts_args=all_incorrect_attempts_args
                            )

        sterr.display_error('dev_errors', 'login', False)
        sterr.display_error('user_errors', 'login', False)
    else:
        st.write("User is already logged in")

if __name__ == '__main__':
    main()
