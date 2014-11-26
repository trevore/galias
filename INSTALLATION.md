# INSTALLATION
galias requires a working python installation. The instructions below will work on Mac and Linux boxes. Windows users are on their own.

## System-wide installation
1. sudo pip install gdata
2. git pull https://github.com/trevore/galias


## Using Virtualenv
1. wget https://github.com/trevore/galias/archive/master.zip
2. unzip master.zip
3. cd galias-master
4. virtualenv env
5. source env/bin/activate
6. pip install -r requirements.txt

For this installation method, please note the following:

1.  You will have to enter this directory and type:

        $ source env/bin/activate (if you are using bash)
each time you start a new shell session.
2. The script must be exectuted via:

        $ python galias.py
to avoid using the system python.



## Configuration

From there you can cd into the galias directory.

In order to save typing there is an config file you can store your
username/password/domain in. These can be passed on the command line or
prompted if you don't provide them.

To use the config file copy example_galias.ini to galias.ini and edit the
file as appropriate.