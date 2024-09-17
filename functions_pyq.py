import pandas as pd
import os
import hashlib
import re
import time

# File paths
USER_DATA_FILE = 'users.csv'
MESSAGE_DATA_FILE = 'messages.csv'
QUICK_CHAT_DATA_FILE = 'quick_chat_messages.csv'
FRIENDS_DATA_FILE = "friends.csv"
ONLINE_PEOPLE = "online.csv"
FRIEND_REQUEST = "friend_request.csv"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_signup(username, password, user_id):
    if len(username) < 5:
        return False, "Username too short."
    if len(password) < 6 or not re.search(r'[A-Z]', password) or not re.search(r'[0-9]', password):
        return False, "Password must be at least 6 characters long, contain an uppercase letter and a number."
    if len(user_id) < 4:
        return False, "ID too short."
    if username.lower() in password.lower():
        return False, "Password cannot contain username."
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores."
    return True, None

def verify_user(username, password):
    if not os.path.exists(USER_DATA_FILE):
        return False, None
    users_df = pd.read_csv(USER_DATA_FILE)
    hashed_password = hash_password(password)
    user = users_df[(users_df['username'] == username) & (users_df['password'] == hashed_password)]
    return not user.empty, user['user_id'].values[0] if not user.empty else None

def is_id_unique(user_id):
    if not os.path.exists(USER_DATA_FILE):
        return True
    users_df = pd.read_csv(USER_DATA_FILE)
    return user_id not in users_df['user_id'].values

def get_username(user_id):
    if not os.path.exists(USER_DATA_FILE):
        return None
    users_df = pd.read_csv(USER_DATA_FILE)
    user = users_df[users_df['user_id'] == user_id]
    return user['username'].values[0] if not user.empty else None

def sign_up(username, password, user_id):
    if not os.path.exists(USER_DATA_FILE):
        users_df = pd.DataFrame(columns=['username', 'password', 'user_id'])
    else:
        users_df = pd.read_csv(USER_DATA_FILE)
    
    if username in users_df['username'].values:
        return False, "Username already exists."
    elif not is_id_unique(user_id):
        return False, "ID already exists."
    else:
        hashed_password = hash_password(password)
        new_user = pd.DataFrame([[username, hashed_password, user_id]], columns=['username', 'password', 'user_id'])
        users_df = pd.concat([users_df, new_user], ignore_index=True)
        users_df.to_csv(USER_DATA_FILE, index=False)
        return True, None

def login(username, password):
    valid, user_id = verify_user(username, password)
    if valid:
        online = pd.read_csv(ONLINE_PEOPLE) if os.path.exists(ONLINE_PEOPLE) else pd.DataFrame(columns=['user_id', 'online?'])
        if user_id not in online['user_id'].values:
            new_guy = pd.DataFrame([[user_id, True]], columns=['user_id', 'online?'])
            online = pd.concat([online, new_guy], ignore_index=True)
            online.to_csv(ONLINE_PEOPLE, index=False)
        return user_id
    return None

def send_message(sender_id, recipient_id, subject, message):
    if not os.path.exists(MESSAGE_DATA_FILE):
        messages_df = pd.DataFrame(columns=['sender_id', 'recipient_id', 'subject', 'message'])
    else:
        messages_df = pd.read_csv(MESSAGE_DATA_FILE)
    
    if is_id_unique(recipient_id):
        return False, "Recipient ID does not exist."
    else:
        new_message = pd.DataFrame([[sender_id, recipient_id, subject, message]], columns=['sender_id', 'recipient_id', 'subject', 'message'])
        messages_df = pd.concat([messages_df, new_message], ignore_index=True)
        messages_df.to_csv(MESSAGE_DATA_FILE, index=False)
        return True, None

def send_quick_chat(sender_id, recipient_id, message):
    if not os.path.exists(QUICK_CHAT_DATA_FILE):
        quick_chat_df = pd.DataFrame(columns=['sender_id', 'recipient_id', 'message'])
    else:
        quick_chat_df = pd.read_csv(QUICK_CHAT_DATA_FILE)
    message = f"{message}\n\nID: {sender_id}"
    new_message = pd.DataFrame([[sender_id, recipient_id, message]], columns=['sender_id', 'recipient_id', 'message'])
    quick_chat_df = pd.concat([quick_chat_df, new_message], ignore_index=True)
    quick_chat_df.to_csv(QUICK_CHAT_DATA_FILE, index=False)
    return True, None

def delete_message(index):
    if not os.path.exists(MESSAGE_DATA_FILE):
        return False, "No messages to delete."
    
    messages_df = pd.read_csv(MESSAGE_DATA_FILE)
    if index >= len(messages_df):
        return False, "Invalid message index."
    
    messages_df = messages_df.drop(index).reset_index(drop=True)
    messages_df.to_csv(MESSAGE_DATA_FILE, index=False)
    return True, None

def view_messages(user_id):
    if not os.path.exists(MESSAGE_DATA_FILE):
        return "No messages found."
    
    messages_df = pd.read_csv(MESSAGE_DATA_FILE)
    received_messages = messages_df[messages_df['recipient_id'] == user_id]
    
    if received_messages.empty:
        return "No messages."
    else:
        messages = ""
        for index, row in received_messages.iterrows():
            sender_username = get_username(row['sender_id'])
            subject = row['subject']
            messages += f"Subject: {subject} (From {sender_username})\n"
            messages += f"From: {sender_username}\n"
            messages += f"Message: {row['message']}\n"
            messages += f"ID: {row['sender_id']}\n\n"
        return messages

def count_new_messages(user_id):
    if not os.path.exists(MESSAGE_DATA_FILE):
        return 0
    
    messages_df = pd.read_csv(MESSAGE_DATA_FILE)
    received_messages = messages_df[messages_df['recipient_id'] == user_id]
    return len(received_messages)

def view_quick_chat(user_id):
    if not os.path.exists(QUICK_CHAT_DATA_FILE):
        return "No Quick Chat messages found."
    
    quick_chat_df = pd.read_csv(QUICK_CHAT_DATA_FILE)
    user_messages = quick_chat_df[(quick_chat_df['sender_id'] == user_id) | (quick_chat_df['recipient_id'] == user_id)]
    
    if user_messages.empty:
        return "No Quick Chat messages."
    else:
        messages = ""
        for index, row in user_messages.iterrows():
            sender_username = get_username(row['sender_id'])
            recipient_username = get_username(row['recipient_id'])
            messages += f"**From:** {sender_username} | **To:** {recipient_username}\n"
            messages += f"**Message:** {row['message']}\n\n"
        return messages

def send_friend_request(friend_id, user_id):
    if not os.path.exists(FRIEND_REQUEST):
        friend_csv = pd.DataFrame(columns=["friender", "friend"])
    else:
        friend_csv = pd.read_csv(FRIEND_REQUEST)
        
    if friend_csv[((friend_csv['friender'] == user_id) & (friend_csv['friend'] == friend_id)) | 
                  ((friend_csv['friend'] == user_id) & (friend_csv['friender'] == friend_id))].empty:
        if not os.path.exists(FRIENDS_DATA_FILE):
            current_friends = pd.DataFrame(columns=["friender", "friended"])
        else:
            current_friends = pd.read_csv(FRIENDS_DATA_FILE)
        
        if current_friends[((current_friends['friender'] == user_id) & (current_friends['friended'] == friend_id)) | 
                           ((current_friends['friended'] == user_id) & (current_friends['friender'] == friend_id))].empty:
            new = pd.DataFrame([[user_id, friend_id]], columns=["friender", "friend"])
            friend_csv = pd.concat([friend_csv, new], ignore_index=True)
            friend_csv.to_csv(FRIEND_REQUEST, index=False)
            return True, "Friend request sent successfully."
        else:
            return False, "You are already friends."
    else:
        return False, "Friend request already exists."

def view_friends(user_id):
    if not os.path.exists(FRIENDS_DATA_FILE):
        return "No friends found."
    
    friends_df = pd.read_csv(FRIENDS_DATA_FILE)
    friends = friends_df[(friends_df['friender'] == user_id) | (friends_df['friended'] == user_id)]
    
    if friends.empty:
        return "No friends."
    else:
        friend_list = ""
        for index, row in friends.iterrows():
            if row['friender'] == user_id:
                friend_list += f"{get_username(row['friended'])} (Currently {is_online(row['friended'])})\n"
            else:
                friend_list += f"{get_username(row['friender'])} (Currently {is_online(row['friender'])})\n"
        return friend_list

def make_friend(friend_id, user_id):
    if not os.path.exists(FRIENDS_DATA_FILE):
        friends_df = pd.DataFrame(columns=["friender", "friended"])
    else:
        friends_df = pd.read_csv(FRIENDS_DATA_FILE)
    
    if is_id_unique(friend_id):
        return False, "Invalid Friend ID."
    
    new_friendship = pd.DataFrame([[user_id, friend_id]], columns=["friender", "friended"])
    friends_df = pd.concat([friends_df, new_friendship], ignore_index=True)
    friends_df.to_csv(FRIENDS_DATA_FILE, index=False)
    return True, "Friend added successfully."

def is_online(user_id):
    if not os.path.exists(ONLINE_PEOPLE):
        return "Offline"
    online_df = pd.read_csv(ONLINE_PEOPLE)
    if user_id in online_df['user_id'].values:
        return "Online"
    else:
        return "Offline"

def clear_quick_chat_cache():
    if os.path.exists(QUICK_CHAT_DATA_FILE):
        os.remove(QUICK_CHAT_DATA_FILE)
