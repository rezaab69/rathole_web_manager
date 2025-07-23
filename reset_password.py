import argparse
import database

def main():
    parser = argparse.ArgumentParser(description="Reset a user's password.")
    parser.add_argument('username', type=str, help="The username of the user to update.")
    parser.add_argument('password', type=str, help="The new password for the user.")
    args = parser.parse_args()

    if database.add_or_update_user(args.username, args.password):
        print(f"Password for user '{args.username}' has been successfully reset.")
    else:
        print(f"Failed to reset password for user '{args.username}'. User may not exist.")

if __name__ == '__main__':
    main()
