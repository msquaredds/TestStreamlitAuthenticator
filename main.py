import streamlit as st
import yaml
from yaml.loader import SafeLoader
import StreamlitAuth as stauth


def main():
    # st.write('Hello World!')

    # import pkg_resources
    # installed_packages = pkg_resources.working_set
    # installed_packages_list = sorted(["%s==%s" % (i.key, i.version)
    #                                   for i in installed_packages])
    # st.write(installed_packages_list)
    # streamlit_package = [i for i in installed_packages if i.key ==
    #                      'streamlitauth']
    # st.write(streamlit_package)

    # use for testing, but ideally we want to store and load from a more
    # secure location, like a database
    with open('config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    st.write(config)

    authenticator = stauth.Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days'],
        config['preauthorized']
    )

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
    # Login
    ##########################################################
    authenticator.login('Login', 'main')

    if st.session_state["authentication_status"]:
        authenticator.logout('Logout', 'main', key='unique_key')
        st.write(f'Welcome *{st.session_state["name"]}*')
        st.title('Some content')
    elif st.session_state["authentication_status"] is False:
        st.error('Username/password is incorrect')
    elif st.session_state["authentication_status"] is None:
        st.warning('Please enter your username and password')




if __name__ == '__main__':
    main()
