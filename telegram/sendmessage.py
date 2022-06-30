import requests

def telegram_bot_sendtext(bot_message):
    send_text = 'https://api.telegram.org/bot$$$/sendMessage?chat_id=$$$&parse_mode=Markdown&text=' + bot_message 
    response = requests.get(send_text)

    telegram_bot_sendtext(str($$$))
