import streamlit as st
import yaml
from yaml.loader import SafeLoader

def main():
    st.write('Hello World!')

    with open('../config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    st.write(config)


if __name__ == '__main__':
    main()
