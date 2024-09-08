import streamlit as st
import hashlib
import os
import pandas as pd
import time
USER_DATA_FILE = 'users.csv'
MESSAGE_DATA_FILE = 'messages.csv'
QUICK_CHAT_DATA_FILE = 'quick_chat_messages.csv'
GROUP_MESSAGES_FILE = 'group_messages.csv'

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
        return (user_id, username)
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
    message = f"""{message}
    \n
    ID: {sender_id}"""
    new_message = pd.DataFrame([[sender_id, recipient_id, message]], columns=['sender_id', 'recipient_id', 'message'])
    quick_chat_df = pd.concat([quick_chat_df, new_message], ignore_index=True)
    quick_chat_df.to_csv(QUICK_CHAT_DATA_FILE, index=False)
    st.rerun()

def send_group_chat_message(group_id, sender_id, message):
    # Check if the group_messages.csv file exists, and if not, create an empty DataFrame
    if not os.path.exists(GROUP_MESSAGES_FILE):
        group_messages_df = pd.DataFrame(columns=['group_id', 'sender_id', 'message'])
    else:
        group_messages_df = pd.read_csv(GROUP_MESSAGES_FILE)

    # Format the message with the sender's ID
    message_formatted = f"""{message}
    
    ID: {sender_id}"""
    
    # Create a new DataFrame row for the message
    new_message = pd.DataFrame([[group_id, sender_id, message_formatted]], columns=['group_id', 'sender_id', 'message'])
    
    # Concatenate the new message with the existing DataFrame
    group_messages_df = pd.concat([group_messages_df, new_message], ignore_index=True)
    
    # Save the updated DataFrame to the CSV file
    group_messages_df.to_csv(GROUP_MESSAGES_FILE, index=False)
    
    # Rerun the app to reflect the changes
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
    st.success("Message deleted successfully")

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
                if st.button(f"Delete Message"):
                    delete_message(index)  # Delete the message and refresh
    time.sleep(2)
    st.rerun()
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

def change_user_id(username, current_password, new_user_id):
    # Verify current password
    valid, user_id = verify_user(username, current_password)
    if not valid:
        st.error("Current password is incorrect.")
        return

def load_groups():
    try:
        return pd.read_csv('groups_messages.csv')
    except FileNotFoundError:
        return pd.DataFrame(columns=['group_id', 'admin_id', 'messages'])

# Save the groups data to the CSV file
def save_groups(df):
    df.to_csv('groups.csv', index=False)

# Create a new group
def create_new_group(admin_id):
    groups_df = load_groups()
    new_group_id = st.text_input("Name Of Group.", help="This Will Be The Group ID")
    new_group = pd.DataFrame([[new_group_id, admin_id, '']], columns=['group_id', 'admin_id', 'messages'])
    updated_groups_df = pd.concat([groups_df, new_group], ignore_index=True)
    save_groups(updated_groups_df)
    return new_group_id

def group_chat_system():
    if 'logged_in_user_id' not in st.session_state:
        st.error("You need to log in first!")
        return

    logged_in_user_id = st.session_state['logged_in_user_id']
    groups_df = load_groups()

    st.subheader("Group Chat System")

    if st.button("Make A New Group"):
        new_group_id = create_new_group(logged_in_user_id)
        st.success(f"New group created with ID: {new_group_id}")

    st.subheader("Your Groups")
    for index, row in groups_df.iterrows():
        if row['admin_id'] == logged_in_user_id:
            st.write(f"Group ID: {row['group_id']}")
            # Add functionality to display and manage messages here
            if st.button(f"View Messages for Group {row['group_id']}"):
                # Display messages for the selected group
                st.write("Messages:")
                st.write(row['messages'])
                st.chat_input("Write A Message")