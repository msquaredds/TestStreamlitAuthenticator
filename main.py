import streamlit as st
import yaml
from yaml.loader import SafeLoader
stauth = __import__("streamlit-authenticator")


def main():
    st.write('Hello World!')

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


if __name__ == '__main__':
    main()
