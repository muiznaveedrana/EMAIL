import streamlit as st
import pandas as pd
import os
from send_email import send_email
import time
import functions


st.set_page_config(
    page_title="My Passive Safe Ultra Max Pro Secruity Double Glazed Account",
    page_icon="📧",
    layout= "wide",
    menu_items={
    'Get Help': 'https://muiz-portfolio.streamlit.app/Contact_Me',
    'Report a bug': 'https://muiz-portfolio.streamlit.app/Contact_Me',
    'About': '''
        My Ultra Max Pro App\n
        A secure app with advanced features!\n
        Shout out to Khalid Sarker :)\n
        Version 2.1.1\n
        The DEVS: muiznaveedrana@gmail.com & ksarker2013@gmail.com\n
        ©️
    ''',
    
}

)


# Use custom HTML with JavaScript to detect click on the link

st.title("⚡ULTRA MAX!⚡")
st.write("__________________________________")

st.sidebar.write(f"{time.strftime('%d/%m/%Y')}")

menu = ["Login", "Sign Up", "Send Message", "Send Message To External Profile", "View Messages", "Quick Chat", "Friends","⚙️ Settings"]
choice = st.sidebar.radio("**Menu**", menu)


# Add the number of new messages to the menu item
if 'logged_in_user_id' in st.session_state:
    st.sidebar.info(f"Logged in as {functions.get_username(st.session_state['logged_in_user_id'])}\n\nID = {st.session_state['logged_in_user_id']}")
if choice == "Sign Up":
    st.subheader("Create Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    user_id = st.text_input("Unique ID")
    if st.button("Sign Up"):
        if functions.verify_signup(username, password, user_id):
            functions.sign_up(username, password, user_id)
            logged_in_user = functions.login(username, password)
            st.session_state['logged_in_user_id'] = logged_in_user[0]
            st.sidebar.info(f"Logged in as {functions.get_username(st.session_state['logged_in_user_id'])}\n\nID = {st.session_state['logged_in_user_id']}")

    functions.check_inactivity()

elif choice == "Login":
    st.subheader("Login")
    #logged_in_user = None
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    #remember_me = st.checkbox("Remember Me")
    if st.button("Login"):
        logged_in_user = functions.login(username, password)
        
        if logged_in_user:
            
            st.session_state['logged_in_user_id'] = logged_in_user[0]
            st.sidebar.info(f"Logged in as {functions.get_username(st.session_state['logged_in_user_id'])}\n\nID = {st.session_state['logged_in_user_id']}")
    functions.check_inactivity()
    #keep

elif choice == "Send Message":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("Send Message")
        recipient_id = st.text_input("Recipient ID")
        subject = st.text_input("Subject")
        message = st.text_area("Message")
        if st.button("Send"):
            functions.send_message(st.session_state['logged_in_user_id'], recipient_id, subject, message)
            functions.check_inactivity()

elif choice == "View Messages":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("View Messages")
        functions.view_messages(st.session_state['logged_in_user_id'])

elif choice == "Send Message To External Profile":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("Send Message To External Profile")
        recipient_email = st.text_input("Recipient Email", help="Only Gmail Supported")
        subject = st.text_input("Subject")
        message = st.text_area("Message")
        if st.button("Send"):
            send_email(message, recipient_email, st.session_state['logged_in_user_id'])
            st.success("External Email Sent!")

elif choice == "Quick Chat":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("Quick Chat! :O")
        recipient_id = st.text_input("What is their ID?")
        functions.view_quick_chat(st.session_state['logged_in_user_id'])
        if recipient_id:
            message = st.chat_input()
            if message:
                functions.send_quick_chat(st.session_state['logged_in_user_id'], recipient_id, message)
        time.sleep(3)
        st.rerun()

elif choice == "⚙️ Settings":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("⚙️ Settings")
        #email_notifications = st.checkbox('Receive Email Notifications')
        #sound_notifications = st.checkbox('Enable Sound Notifications for Messages')
        if st.button('Change Password'):
        # Inputs for current and new passwords
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            repeat_new_password = st.text_input("Repeat New Password", type="password")
            
            # Add a button to confirm password change
            if st.button('Confirm Change'):
                # Check if all fields are filled
                if not current_password or not new_password or not repeat_new_password:
                    st.error("Please fill in all fields.")
                elif new_password != repeat_new_password:
                    st.error("New passwords do not match.")
                else:
                    # Verify the current password
                    valid, user_id = functions.verify_user(st.session_state['logged_in_username'], current_password)
                    if not valid:
                        st.error("Current password is incorrect.")
                    else:
                        # Update the password
                        hashed_new_password = functions.hash_password(new_password)
                        if not os.path.exists(functions.USER_DATA_FILE):
                            st.error("User data file does not exist.")
                        else:
                            users_df = pd.read_csv(functions.USER_DATA_FILE)
                            users_df.loc[users_df['user_id'] == user_id, 'password'] = hashed_new_password
                            users_df.to_csv(functions.USER_DATA_FILE, index=False)
                            st.success("Password changed successfully!")
        
        if st.button("SIGN OUT"):
                # Clear session state
            # You can define this user ID or dynamically determine it
            functions.remove_user_from_online(st.session_state['logged_in_user_id'])
            del st.session_state['logged_in_user_id']
            #functions.check_inactivity()
            st.success("You have been signed out.")

elif choice == "Friends":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("Friends")
        friend_id = st.text_input("Friend ID")
        if st.button("Send Friend Request"):
            functions.send_friend_request(friend_id, st.session_state["logged_in_user_id"])
        with st.expander("Friend Requests"):
            functions.view_friend_requests(st.session_state['logged_in_user_id'])
            #st.write("TEST")
        functions.view_friends(st.session_state["logged_in_user_id"])
    functions.check_inactivity()

functions.check_inactivity()