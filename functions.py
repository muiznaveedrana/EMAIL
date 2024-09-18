import streamlit as st
import hashlib
import os
import pandas as pd
import time
import re

USER_DATA_FILE = 'users.csv'
MESSAGE_DATA_FILE = 'messages.csv'
QUICK_CHAT_DATA_FILE = 'quick_chat_messages.csv'
FRIENDS_DATA_FILE = "friends.csv"
ONLINE_PEOPLE = "online.csv"
FRIEND_REQUEST = "friend_request.csv"

def check_inactivity(timeout_seconds=300):
    if 'logged_in_user_id' in st.session_state:
        if 'last_interaction' not in st.session_state:
            st.session_state['last_interaction'] = time.time()
        if time.time() - st.session_state['last_interaction'] > timeout_seconds:
            st.error("Session expired due to inactivity.")
            remove_user_from_online(st.session_state['logged_in_user_id'])
            st.stop()
        else:
            st.session_state['last_interaction'] = time.time()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_signup(username, password, user_id):
    if len(username) < 5:
        st.error("Username Too Short.")
        return False
    if len(password) < 6 or not re.search(r'[A-Z]', password) or not re.search(r'[0-9]', password):
        st.error("Password must be at least 6 characters long, contain an uppercase letter and a number")
        return False
    if len(user_id) < 4:
        st.error("ID Too Short")
        return False
    if username.lower() in password.lower():
        st.error("Password cannot contain username.")
        return False
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        st.error("Username can only contain letters, numbers, and underscores.")
        return False
    return True
    

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
        st.session_state['logged_in_user_id'] = user_id
        st.success(f'Login successful! Welcome {username} (ID: {user_id})')
        online = pd.read_csv(ONLINE_PEOPLE)
        if user_id not in online['user_id'].values:
            new_guy = pd.DataFrame()
            new_guy['user_id'] = [user_id]
            new_guy['online?'] = [True]
            online = pd.concat([online, new_guy], ignore_index=False)
            online.to_csv(ONLINE_PEOPLE, index=False)
        
        return user_id, username
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

    ID: {sender_id}
    """
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
                if st.button(f"Delete Message", key = f"HOLA {index}"):
                    delete_message(index)  # Delete the message and refresh
    check_inactivity()
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

def send_friend_request(friend_id, user_id):
    friend_csv = pd.read_csv(FRIEND_REQUEST)
    if friend_csv[((friend_csv['friender'] == user_id) & (friend_csv['friend'] == friend_id)) | 
                  ((friend_csv['friend'] == user_id) & (friend_csv['friender'] == friend_id))].empty:
        current_friends = pd.read_csv(FRIENDS_DATA_FILE)
        if current_friends[((current_friends['friender'] == user_id) & (current_friends['friended'] == friend_id)) | 
                       ((current_friends['friended'] == user_id) & (current_friends['friender'] == friend_id))].empty:
            new = pd.DataFrame([[user_id, friend_id]], columns=["friender", "friend"])
            friend_csv = pd.concat([friend_csv, new], ignore_index=True)
            friend_csv.to_csv(FRIEND_REQUEST, index=False)
            st.success("Friend Request Sent Succesfully")
            st.balloons()
        else:
            st.error("You Are Already Friends. >:(")
    else:
        st.error("Something went wrong. >:(")

def view_friends(user_id):
    quick_chat_df = pd.read_csv(FRIENDS_DATA_FILE)
    friends = quick_chat_df[(quick_chat_df['friender'] == user_id) | (quick_chat_df['friended'] == user_id)]
    
    if friends.empty:
        st.write("No Friends :O")
    else:
        for index, row in friends.iterrows():
            sender_username = get_username(row['friender'])
            recipient_username = get_username(row['friended'])
            
            with st.chat_message('user'):
                if sender_username == get_username(user_id):
                    st.write(f"{recipient_username}")
                    st.write(f"Currently {is_online(row['friended'])}")  # Check recipient
                else:
                    st.write(f"**{sender_username}**")
                    st.write(f"{is_online(row['friender'])}")  # Check sender


    time.sleep(5)
    st.rerun()

def make_friend(friend_id, user_id):
    if is_id_unique(friend_id):
        st.error('Friend ID does not exist.')
    else:
        messages_df = pd.read_csv(FRIENDS_DATA_FILE)
        new_message = pd.DataFrame([[friend_id, user_id]], columns=['friender', 'friended'])
        messages_df = pd.concat([messages_df, new_message], ignore_index=True)
        messages_df.to_csv(FRIENDS_DATA_FILE, index=False)
        st.balloons()

def view_friend_requests(user_id):

    # Read friend requests from the CSV file
    friend_requests = pd.read_csv(FRIEND_REQUEST)

    # Filter for friend requests where the 'friend' is the current user (user_id)
    friends = friend_requests[friend_requests['friend'] == user_id]
    if not friends.empty:
    # Iterate over each friend request
        for index, row in friends.iterrows():
            friender = row['friender']  # Extract the friender's ID
            
            # Display the friend request message
            st.write(f"You have a new friend request from {friender}")
            
            # Accept and Decline buttons
            if st.button(f"Accept✅", key = index):
                # Get the friender's ID to accept
                friend_requests = friend_requests[friend_requests['friend'] != user_id]
                friend_requests.to_csv(FRIEND_REQUEST, index=False)
                friend_id = friender
                make_friend(friend_id, user_id)  
                time.sleep(2)
                st.rerun()
            if st.button(f"Decline❌", key = f"{index}Hello"):
                # Remove friend request from the CSV
                friend_requests = friend_requests[friend_requests['friend'] != user_id]
                friend_requests.to_csv(FRIEND_REQUEST, index=False)
                time.sleep(2)
                st.rerun()
    else:
        st.info("No Friend Requests")

def is_online(user_id):

    file = pd.read_csv(ONLINE_PEOPLE)
    
    # Assuming user IDs are in a column called 'user_id'
    online_ids = file['user_id'].tolist()  # Convert the user_id column to a list

    # Return 'Online' if the user_id is found in online_ids
    return "Online" if user_id in online_ids else "Offline"

def remove_user_from_online(user_id):
    # Read the online.csv file into a DataFrame
    online_df = pd.read_csv('online.csv')
    
    # Remove the user from the online list
    online_df = online_df[online_df['user_id'] != user_id]
    
    # Save the updated DataFrame back to the CSV file
    online_df.to_csv('online.csv', index=False)
