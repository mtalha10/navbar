# main.py
import streamlit as st
from config.paths import NAVBAR_PATHS, SETTINGS
import utils as utl
from views import home, analysis, zap, schedule_page

# Set page configuration first
st.set_page_config(layout="wide", page_title='App')

utl.inject_custom_css()
utl.navbar_component()

def navigation():
    route = utl.get_current_route()
    if route == "home":
        home.load_view()
    elif route == "zap":
        zap.show_zap_page()
    elif route == "analysis":
        analysis.load_view()
    elif route == "Schedule Page":
        schedule_page.show_schedule_page()
    elif route is None:
        home.load_view()

navigation()
