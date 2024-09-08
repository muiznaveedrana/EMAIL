import streamlit as st
import pandas as pd
import hashlib
import os
from send_email import send_email

# CSV filenames
USER_DATA_FILE = 'users.csv'
MESSAGE_DATA_FILE = 'messages.csv'
QUICK_CHAT_DATA_FILE = 'quick_chat_messages.csv'

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to verify user credentials
def verify_user(username, password):
    if not os.path.exists(USER_DATA_FILE):
        return False, None
    users_df = pd.read_csv(USER_DATA_FILE)
    hashed_password = hash_password(password)
    user = users_df[(users_df['username'] == username) & (users_df['password'] == hashed_password)]
    return not user.empty, user['user_id'].values[0] if not user.empty else None

# Function to check if ID is unique
def is_id_unique(user_id):
    if not os.path.exists(USER_DATA_FILE):
        return True
    users_df = pd.read_csv(USER_DATA_FILE)
    return user_id not in users_df['user_id'].values

# Function to get username from user_id
def get_username(user_id):
    if not os.path.exists(USER_DATA_FILE):
        return None
    users_df = pd.read_csv(USER_DATA_FILE)
    user = users_df[users_df['user_id'] == user_id]
    return user['username'].values[0] if not user.empty else None

# Sign-up system
def sign_up(username, password, user_id):
    if not os.path.exists(USER_DATA_FILE):
        users_df = pd.DataFrame(columns=['username', 'password', 'user_id'])
    else:
        users_df = pd.read_csv(USER_DATA_FILE)
        
    if username in users_df['username'].values:
        st.error('Username already exists. Please choose another.')
    elif not is_id_unique(user_id):
        st.error('ID already exists. Please choose another.')
    else:
        hashed_password = hash_password(password)
        new_user = pd.DataFrame([[username, hashed_password, user_id]], columns=['username', 'password', 'user_id'])
        users_df = pd.concat([users_df, new_user], ignore_index=True)
        users_df.to_csv(USER_DATA_FILE, index=False)
        st.success('Sign-up successful!')
        send_message("The System!", user_id, "Thank You For Signing Up!", "Welcome To Your Passive Safe Ultra Max Pro Secruity Double Glazed Account! :O\n You Now Rock :~)")

# Login system
def login(username, password):
    valid, user_id = verify_user(username, password)
    if valid:
        st.success(f'Login successful! Welcome {username} (ID: {user_id})')
        return user_id
    else:
        st.error('Invalid username or password.')
        return None

# Function to send a message
def send_message(sender_id, recipient_id, subject, message):
    if not os.path.exists(MESSAGE_DATA_FILE):
        messages_df = pd.DataFrame(columns=['sender_id', 'recipient_id', 'subject', 'message'])
    else:
        messages_df = pd.read_csv(MESSAGE_DATA_FILE)
        
    if is_id_unique(recipient_id):
        st.error('Recipient ID does not exist.')
    else:
        new_message = pd.DataFrame([[sender_id, recipient_id, subject, message]], columns=['sender_id', 'recipient_id', 'subject', 'message'])
        messages_df = pd.concat([messages_df, new_message], ignore_index=True)
        messages_df.to_csv(MESSAGE_DATA_FILE, index=False)
        st.success('Message sent successfully!')

# Function to send a Quick Chat message
def send_quick_chat(sender_id, recipient_id, message):
    if not os.path.exists(QUICK_CHAT_DATA_FILE):
        quick_chat_df = pd.DataFrame(columns=['sender_id', 'recipient_id', 'message'])
    else:
        quick_chat_df = pd.read_csv(QUICK_CHAT_DATA_FILE)
        
    new_message = pd.DataFrame([[sender_id, recipient_id, message]], columns=['sender_id', 'recipient_id', 'message'])
    quick_chat_df = pd.concat([quick_chat_df, new_message], ignore_index=True)
    quick_chat_df.to_csv(QUICK_CHAT_DATA_FILE, index=False)
    st.rerun()

# Function to delete a message
def delete_message(index):
    if not os.path.exists(MESSAGE_DATA_FILE):
        st.error("No messages to delete.")
        return
    
    messages_df = pd.read_csv(MESSAGE_DATA_FILE)
    if index >= len(messages_df):
        st.error("Invalid message index.")
        return
    
    messages_df = messages_df.drop(index).reset_index(drop=True)
    messages_df.to_csv(MESSAGE_DATA_FILE, index=False)
    st.success("Message deleted successfully! Please reload to view the difference :O")
    st.rerun()

# Function to view received messages
def view_messages(user_id):
    if not os.path.exists(MESSAGE_DATA_FILE):
        st.write("No messages found.")
        return
    
    messages_df = pd.read_csv(MESSAGE_DATA_FILE)
    received_messages = messages_df[messages_df['recipient_id'] == user_id]
    
    if received_messages.empty:
        st.write("No messages.")
    else:
        for index, row in received_messages.iterrows():
            sender_username = get_username(row['sender_id'])
            subject = row['subject']
            
            # Create an expander to view/collapse the message
            with st.expander(f"Subject: {subject} (From {sender_username})", expanded=False):
                st.write(f"From: {sender_username}")
                st.write(f"Message: {row['message']}")
                st.write(f"ID: {row['sender_id']}")
                if st.button(f"Delete Message", key=f"delete_{index}"):
                    delete_message(index)  # Delete the message and refresh

# Function to count new messages
def count_new_messages(user_id):
    if not os.path.exists(MESSAGE_DATA_FILE):
        return 0
    
    messages_df = pd.read_csv(MESSAGE_DATA_FILE)
    received_messages = messages_df[messages_df['recipient_id'] == user_id]
    return len(received_messages)

# Function to view Quick Chat messages
def view_quick_chat(user_id):
    if not os.path.exists(QUICK_CHAT_DATA_FILE):
        st.write("No Quick Chat messages found.")
        return
    
    quick_chat_df = pd.read_csv(QUICK_CHAT_DATA_FILE)
    user_messages = quick_chat_df[(quick_chat_df['sender_id'] == user_id) | (quick_chat_df['recipient_id'] == user_id)]
    
    if user_messages.empty:
        st.write("No Quick Chat messages.")
    else:
        for index, row in user_messages.iterrows():
            sender_username = get_username(row['sender_id'])
            recipient_username = get_username(row['recipient_id'])
            with st.chat_message('human'):
                st.write(f"**From:** {sender_username} | **To:** {recipient_username}")
                st.write(f"**Message:** {row['message']}")

# Streamlit UI
st.title("Internal Email App")

# Sidebar menu for navigation
menu = ["Sign Up", "Login", "Send Message", "Send Message To External Profile", "View Messages", "Quick Chat (NEW)"]
choice = st.sidebar.selectbox("Menu", menu)

# Add the number of new messages to the menu item
if 'logged_in_user_id' in st.session_state:
    new_messages_count = count_new_messages(st.session_state['logged_in_user_id'])
    menu[4] = f"View Messages ({new_messages_count})"

if choice == "Sign Up":
    st.subheader("Create Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    user_id = st.text_input("Unique ID")
    if st.button("Sign Up"):
        sign_up(username, password, user_id)

elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        logged_in_user_id = login(username, password)
        
        if logged_in_user_id:
            st.sidebar.write(f"Logged in as {logged_in_user_id}")
            st.session_state['logged_in_user_id'] = logged_in_user_id
            # Update the number of new messages after login
            new_messages_count = count_new_messages(logged_in_user_id)
            menu[4] = f"View Messages ({new_messages_count})"

elif choice == "Send Message":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("Send Message")
        recipient_id = st.text_input("Recipient ID")
        subject = st.text_input("Subject")
        message = st.text_area("Message")
        if st.button("Send"):
            send_message(st.session_state['logged_in_user_id'], recipient_id, subject, message)

elif choice == "View Messages":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("View Messages")
        view_messages(st.session_state['logged_in_user_id'])

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

elif choice == "Quick Chat (NEW)":
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
    else:
        st.subheader("Quick Chat! :O")
        recipient_id = st.text_input("What is their ID?")
        view_quick_chat(st.session_state['logged_in_user_id'])
        
        if recipient_id:
            message = st.chat_input()
            if message:
                send_quick_chat(st.session_state['logged_in_user_id'], recipient_id, message)
       
