"""
Used to test all the functions of the StreamlitAuth package.
This includes testing the original, unaltered package (see the bottom),
as well as all updates.
"""

import json
import streamlit as st
import yaml

from datetime import date
from yaml.loader import SafeLoader

import StreamlitAuth as stauth


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

    # from google.oauth2 import service_account
    # scopes = ['https://www.googleapis.com/auth/cloudkms']
    # our_credentials = 'teststreamlitauth-412915-9579af1e153c.json'
    # creds = service_account.Credentials.from_service_account_file(
    #     our_credentials, scopes=scopes)

    authenticator.register_user('main', False, 'generic',
                                email_user='gmail', website_name='SharpShares',
                                website_email='alex.melesko@msquaredds.com',
                                oauth2_credentials_secrets_file=st.secrets[
                                    'GMAIL'])
                                # project_id='teststreamlitauth-412915',
                                # location_id='us-central1',
                                # key_ring_id='testkeyring',
                                # key_id='testkey',
                                # kms_credentials=creds)

    if 'authenticator_usernames' in st.session_state:
        st.write('authenticator_usernames',
                 st.session_state['authenticator_usernames'])
    if 'authenticator_emails' in st.session_state:
        st.write('authenticator_emails',
                 st.session_state['authenticator_emails'])
    if 'authenticator_user_credentials' in st.session_state:
        st.write('authenticator_user_credentials',
                 st.session_state['authenticator_user_credentials'])
    if 'authenticator_preauthorized' in st.session_state:
        st.write('authenticator_preauthorized',
                 st.session_state['authenticator_preauthorized'])





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
