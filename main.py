"""
Used to test all the functions of the StreamlitAuth package starting from
version 0.4.0 / 09_17_2024 (and archived version was used for all tests
prior to that).
"""

import streamlit as st


def main():
    st.set_page_config(page_title="StUser Testing", layout="wide")
    title_cols = st.columns(3)
    with title_cols[1]:
        title_writing = "StUser Testing"
        title_format = f'<p style="text-align: center; font-family: ' \
                       f'Arial; font-size: 40px; ' \
                       f'font-weight: bold;">{title_writing}</p>'
        st.markdown(title_format, unsafe_allow_html=True)

    pages = [st.Page("/pages/Authentication.py", "Authentication"),
             st.Page("/pages/EmailVerification.py", "Email Verification")]
    pg = st.navigation(pages)
    pg.run()


if __name__ == '__main__':
    main()
