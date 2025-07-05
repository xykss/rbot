# RBOT C2

If you think this is a backdoor please submit the proof as an issue or fork to this repository otherwise fuck off, sincerely bleach.

2328 Lines of code and counting

Non-profit C2 for anyone trying to build from scratch.
It’s free — use it. Don’t whine because others are too.
Why pay for what’s free? Makes no sense.
Don’t be that guy :)

## Setup

Setup Video - https://www.youtube.com/xxxxx

- first step - mysql

  *need to setup mysql?* Go Here: https://dev.mysql.com/doc/mysql-installation-excerpt/5.7/en/
  
  > You may need to allow localhost to connect if you do not allow remote connections here is a command that should allow you to whitelist yourself 
  > 
  > `$ mysql -u USERNAME -pSECRET_PASSWORD mysql -e "grant ALL on *.* to USERNAME@'localhost' IDENTIFIED by 'SECRET_PASSWORD';"`

  > If you have too many file descriptors open change to however much you need
  > 
  > `$ ulimit -n 999999`

  `$ mysql -u USERNAME -p SECRET_PASSWORD rbot`
  *that's all there is too it folks*

- second step - customize!
  go ahead you're already good to go!

*original made in a week flat*
