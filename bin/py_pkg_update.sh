#!/bin/bash

cp -r _tp_modules/tweepy .
rm -rf _tp_modules/* && \
sudo pip install -r requirements.txt -t _tp_modules/
cp -r tweepy _tp_modules/
rm -rf tweepy
