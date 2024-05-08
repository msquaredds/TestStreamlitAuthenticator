"""
Used to test all the functions of the StreamlitAuth package.
This includes testing the original, unaltered package (see the bottom),
as well as all updates.
"""

import json
import pandas as pd
import streamlit as st
import yaml

from datetime import date
from google.cloud import bigquery
from google.oauth2 import service_account
from typing import Union
from yaml.loader import SafeLoader

import StreamlitAuth as stauth


def _store_df_bigquery(user_credentials: dict, bq_creds: dict, project: str,
                       dataset: str, table_name: str,
                       if_exists: str='append') -> Union[None, str]:
    """
    Creating a test function that allows for storing data, since we will
        try passing this function into the register_user function.
    :param user_credentials: The user credentials to store.
    :param bq_creds: The credentials to access the BigQuery project. These
        should, at a minimum, have the role of "BigQuery Data Editor".
    :param project: The project to store the data in.
    :param dataset: The dataset to store the data in.
    :param table_name: The name of the table to store the data in.
    :param if_exists: What to do if the table already exists.
        Can be 'append', 'replace', or 'fail'. Default is 'append'.
    :return: None if successful, error message if not.
    """
    # turn the user credentials into a dataframe
    user_credentials['username'] = [user_credentials['username']]
    user_credentials['email'] = [user_credentials['email']]
    user_credentials['password'] = [user_credentials['password']]
    # we to add a utc timestamp
    user_credentials['datetime'] = [pd.to_datetime('now', utc=True)]
    df = pd.DataFrame(user_credentials)

    # connect to the database
    scope=['https://www.googleapis.com/auth/bigquery']
    try:
        creds = service_account.Credentials.from_service_account_info(
            bq_creds, scopes=scope)
    except Exception as e:
        return f"Error loading credentials: {str(e)}"

    try:
        client = bigquery.Client(credentials=creds)
    except Exception as e:
        return f"Error creating the BigQuery client: {str(e)}"

    # set up table_id
    table_id = project + "." + dataset + "." + table_name
    # determine behavior if table already exists
    if if_exists == 'append':
        write_disposition = 'WRITE_APPEND'
    elif if_exists == 'replace':
        write_disposition = 'WRITE_TRUNCATE'
    else:
        write_disposition = 'WRITE_EMPTY'
    # set up the config
    job_config = bigquery.LoadJobConfig(
        write_disposition=write_disposition
    )

    # store
    try:
        job = client.load_table_from_dataframe(df, table_id,
                                               job_config=job_config)
        job.result()
    except Exception as e:
        return f"Error storing BigQuery data: {str(e)}"

    # test if we can access the table / double check that it saved
    try:
        _ = client.get_table(table_id)  # Make an API request.
    except Exception as e:
        return f"Error getting the saved table from BigQuery: {str(e)}"


def main():
    # st.write('Hello World!')

    # this section is used to check the installed packages, including the
    # version of streamlitauth
    ######################################################################
    # import pkg_resources
    # installed_packages = pkg_resources.working_set
    # installed_packages_list = sorted(["%s==%s" % (i.key, i.version)
    #                                   for i in installed_packages])
    # st.write(installed_packages_list)
    # streamlit_package = [i for i in installed_packages if i.key ==
    #                      'streamlitauth']
    # st.write(streamlit_package)
    ######################################################################

    # use for testing, but ideally we want to store and load from a more
    # secure location, like a database
    with open('config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    #st.write("config", config)

    # put usernames and emails into a list
    usernames = [i for i in config['credentials']['usernames'].keys()]
    emails = [config['credentials']['usernames'][i]['email']
              for i in usernames]

    #st.write("usernames", usernames)
    #st.write("emails", emails)

    if 'authenticator_usernames' not in st.session_state:
        st.session_state['authenticator_usernames'] = usernames
    if 'authenticator_emails' not in st.session_state:
        st.session_state['authenticator_emails'] = emails
    if 'authenticator_preauthorized' not in st.session_state:
        st.session_state['authenticator_preauthorized'] = config[
            'preauthorized']['emails']

    authenticator = stauth.Authenticate(
        usernames_session_state='authenticator_usernames',
        emails_session_state='authenticator_emails',
        user_credentials_session_state='authenticator_user_credentials',
        preauthorized_session_state='authenticator_preauthorized',
        cookie_name=config['cookie']['name'],
        cookie_key=config['cookie']['key'],
        cookie_expiry_days=config['cookie']['expiry_days']
    )

    ##########################################################
    # Sign Up
    ##########################################################
    # we tested all versions of inputs:
    # 'main' vs 'sidebar'
    # True vs False
    # 'generic' vs 'google'
    # we also tested the decrypt function, which is not used in the
    # register_user function, but was created for completeness
    # some of the email and save functionality was originally tested
    # separately, but hten tested here too

    if ('stauth' in st.session_state and
            'dev_errors' in st.session_state['stauth'].keys() and
            'register_user' in st.session_state['stauth']['dev_errors'].keys()):
        st.error(f"dev_error: "
                 f"{st.session_state['stauth']['dev_errors']['register_user']}")
    elif ('stauth' in st.session_state and
          'user_errors' in st.session_state['stauth'].keys() and
          'register_user' in st.session_state['stauth']['user_errors'].keys()):
        st.error(f"user_error: "
                 f"{st.session_state['stauth']['user_errors']['register_user']}")

    # here we pull in the credentials for the google cloud service account
    # that allows us to access the KMS (key management service) to encrypt
    # and decrypt data.
    # in this case, we used a service account to do so.
    # this service account must be permissioned (at a minimum) as a
    # "Cloud KMS CryptoKey Encrypter/Decrypter" in order to use the KMS.
    # our_credentials is just a file that stores the key info (the service
    # account key, not the KMS key) in a JSON file.

    from google.oauth2 import service_account
    kms_scopes = ['https://www.googleapis.com/auth/cloudkms']
    kms_creds = service_account.Credentials.from_service_account_info(
        st.secrets['KMS'], scopes=kms_scopes)
    # OLD: our_credentials = 'service_account_key_file.json'
    # OLD: creds = service_account.Credentials.from_service_account_file(
    #     our_credentials, scopes=scopes)


    authenticator.register_user('main', False, 'google',
                                encrypt_args={
                                    'project_id': 'teststreamlitauth-412915',
                                    'location_id': 'us-central1',
                                    'key_ring_id': 'testkeyring',
                                    'key_id': 'testkey',
                                    'kms_credentials': kms_creds},
                                email_user='sendgrid',
                                email_inputs={
                                    'website_name': 'SharpShares',
                                    'website_email':
                                        'hello@sharpshares.com'},
                                # email_creds={
                                #     'oauth2_credentials_secrets_dict':
                                #         st.secrets['GMAIL']}
                                email_creds={'sendgrid_api_key':
                                             st.secrets['SENDGRID'][
                                                 'sendgrid_api_key']},
                                cred_save_function='bigquery',
                                cred_save_args={
                                    'bq_creds': st.secrets['BIGQUERY'],
                                    'project': 'teststreamlitauth-412915',
                                    'dataset': 'test_credentials',
                                    'table_name': 'user_credentials'})


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

        # here we tested turning the credentials dictionary into a
        # dataframe and also making sure that once we put it into a
        # dataframe we could pull it back out and decrypt it
        # turn the dict into a dataframe
        save_dict = st.session_state['authenticator_user_credentials'].copy()
        save_dict['username'] = [save_dict['username']]
        save_dict['email'] = [save_dict['email']]
        save_dict['password'] = [save_dict['password']]
        # we to add a utc timestamp
        save_dict['datetime'] = [pd.to_datetime('now', utc=True)]
        save_df = pd.DataFrame(save_dict)
        st.write("save_df", save_df)

        # # pull out the str username
        # username = save_df['username'].values[0]
        # st.write("username", username)
        # # decrypt the username
        # decryptor = stauth.GoogleEncryptor('teststreamlitauth-412915',
        #                                    'us-central1',
        #                                    'testkeyring',
        #                                    'testkey',
        #                                    kms_creds)
        # decrypted_username = decryptor.decrypt(username)
        # st.write("decrypted_username", str(
        #     decrypted_username.plaintext).replace("b'", "").replace("'", ""))

    ##########################################################
    # Login
    ##########################################################
    st.write('---')
    authenticator.login('main')





    ######################################################################
    ######################################################################
    ######################################################################
    # EVERYTHING BELOW HERE IS TESTING FOR THE ORIGINAL PACKAGE
    ######################################################################
    # This was forked from the original package
    # (https://github.com/mkhorasani/Streamlit-Authenticator)
    # and tested before any changes were made
    ######################################################################
    ######################################################################

    ##########################################################
    # Sign Up - No Preauthorization
    ##########################################################
    # try:
    #     if authenticator.register_user('Register user',
    #                                    preauthorization=False):
    #         st.success('User registered successfully')
    # except Exception as e:
    #     st.error(e)
    #
    # st.write(config['credentials'])

    ##########################################################
    # Sign Up - Yes Preauthorization
    ##########################################################
    # try:
    #     if authenticator.register_user('Register user'):
    #         st.success('User registered successfully')
    # except Exception as e:
    #     st.error(e)
    #
    # st.write(config)

    ##########################################################
    # Login / Logout / Authentication Status
    ##########################################################
    # authenticator.login('Login', 'main')
    #
    # if st.session_state["authentication_status"]:
    #     authenticator.logout('Logout', 'main', key='unique_key')
    #     st.write(f'Welcome *{st.session_state["name"]}*')
    #     st.title('Some content')
    #     authenticator.token['exp_date'] = date.fromtimestamp(
    #         authenticator.token['exp_date'])
    #     st.write(authenticator.token)
    # elif st.session_state["authentication_status"] is False:
    #     st.error('Username/password is incorrect')
    # elif st.session_state["authentication_status"] is None:
    #     st.warning('Please enter your username and password')

    ##########################################################
    # Forgot Username
    ##########################################################
    # try:
    #     username_of_forgotten_username, email_of_forgotten_username = \
    #         authenticator.forgot_username('Forgot username')
    #     if username_of_forgotten_username:
    #         st.success('Username to be sent securely')
    #         # Username should be transferred to user securely
    #     else:
    #         st.error('Email not found')
    # except Exception as e:
    #     st.error(e)

    ##########################################################
    # Forgot Password
    ##########################################################
    # try:
    #     (username_of_forgotten_password, email_of_forgotten_password,
    #      new_random_password) = authenticator.forgot_password(
    #          'Forgot password')
    #     if username_of_forgotten_password:
    #         st.success('New password to be sent securely')
    #         st.write(username_of_forgotten_password)
    #         st.write(email_of_forgotten_password)
    #         st.write(new_random_password)
    #         # Random password should be transferred to user securely
    #     else:
    #         st.error('Username not found')
    # except Exception as e:
    #     st.error(e)

    ##########################################################
    # Change Password (run login above too)
    ##########################################################
    # if st.session_state["authentication_status"]:
    #     try:
    #         if authenticator.reset_password(st.session_state["username"],
    #                                         'Reset password'):
    #             st.success('Password modified successfully')
    #             st.write(config['credentials'])
    #     except Exception as e:
    #         st.error(e)

    ##########################################################
    # Change User's Name or Email (run login above too)
    ##########################################################
    # if st.session_state["authentication_status"]:
    #     try:
    #         if authenticator.update_user_details(
    #                 st.session_state["username"], 'Update user details'):
    #             st.success('Entries updated successfully')
    #             st.write(authenticator.credentials[
    #                      'usernames'][st.session_state["username"]])
    #     except Exception as e:
    #         st.error(e)


if __name__ == '__main__':
    main()
