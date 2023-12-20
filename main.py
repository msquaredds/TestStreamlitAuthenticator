import streamlit as st
import streamlit_authenticator_test as stauth
import yaml
from yaml.loader import SafeLoader

def main():
    st.write('Hello World!')

    with open('../config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    st.write(config)

    authenticator = stauth.Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days'],
        config['preauthorized']
    )


if __name__ == '__main__':
    main()
