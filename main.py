import streamlit as st
import pandas as pd
import os
from send_email import send_email
import time
import functions
st.set_page_config(
    page_title="My Passive Safe Ultra Max Pro Secruity Double Glazed Account",
    page_icon="📧",
    layout= "wide"
)



# Timer function to check inactivity


st.title("⚡ULTRA MAX!⚡")
st.write("__________________________________")

menu = ["Sign Up", "Login", "Send Message", "Send Message To External Profile", "View Messages", "Quick Chat", "Friends", "⚙️ Settings"]
choice = st.sidebar.radio("**Menu**", menu)
# Add the number of new messages to the menu item
if 'logged_in_user_id' in st.session_state:
    new_messages_count = functions.count_new_messages(st.session_state['logged_in_user_id'])
    menu[4] = f"View Messages ({new_messages_count})"

if choice == "Sign Up":
    st.subheader("Create Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    user_id = st.text_input("Unique ID")
    if st.button("Sign Up"):
        if functions.verify_signup(username, password, user_id):
            functions.sign_up(username, password, user_id)
    functions.check_inactivity()

elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        logged_in_user = functions.login(username, password)
        
        if logged_in_user:
            st.sidebar.write(f"Logged in as {logged_in_user[1]}")
            st.session_state['logged_in_user_id'] = logged_in_user[0]
            # Update the number of new messages after login
            new_messages_count = functions.count_new_messages(logged_in_user[0])
            menu[4] = f"View Messages ({new_messages_count})"
    functions.check_inactivity()

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
        if st.button("Clear Cache"):
            if st.text_input("WHAT IS THE SYSTEM PASSWORD", type="password") == "Muiz2013":
                empty_df = pd.DataFrame(columns=['sender_id', 'recipient_id', 'message'])
                empty_df.to_csv(functions.QUICK_CHAT_DATA_FILE, index=False)
                st.success("Quick Chat Cache Cleared!")
                st.rerun()
        recipient_id = st.text_input("What is their ID?")
        functions.view_quick_chat(st.session_state['logged_in_user_id'])
        if recipient_id:
            message = st.chat_input()
            if message:
                functions.send_quick_chat(st.session_state['logged_in_user_id'], recipient_id, message)
            time.sleep(2)
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