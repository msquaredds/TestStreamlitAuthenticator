import streamlit as st
import yaml
from yaml.loader import SafeLoader
#import StreamlitAuth as stauth


def main():
    st.write('Hello World!')

    import pkg_resources
    installed_packages = pkg_resources.working_set
    installed_packages_list = sorted(["%s==%s" % (i.key, i.version)
                                      for i in installed_packages])
    st.write(installed_packages_list)

    # use for testing, but ideally we want to store and load from a more
    # secure location, like a database
    with open('config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    st.write(config)

    # authenticator = stauth.Authenticate(
    #     config['credentials'],
    #     config['cookie']['name'],
    #     config['cookie']['key'],
    #     config['cookie']['expiry_days'],
    #     config['preauthorized']
    # )


if __name__ == '__main__':
    main()
