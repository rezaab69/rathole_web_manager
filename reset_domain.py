import database

def main():
    if database.delete_setting('domain_name'):
        print("Domain name has been successfully reset.")
    else:
        print("Failed to reset domain name.")

if __name__ == '__main__':
    main()
