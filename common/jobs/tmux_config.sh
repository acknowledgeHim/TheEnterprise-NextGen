tmux new-session -s "the_enterprise" -d
tmux split-window -h
tmux split-window -v
tmux -2 attach-session -d


#!/bin/sh
#
# Setup a work space called `work` with two windows
# first window has 3 panes.
# The first pane set at 65%, split horizontally, set to api root and running vim
# pane 2 is split at 25% and running redis-server
# pane 3 is set to api root and bash prompt.
# note: `api` aliased to `cd ~/path/to/work`
#
session="the_enterprise"

# set up tmux
tmux start-server

# create a new tmux session, starting vim from a saved session in the new window
tmux new-session -d -s $session -n vim

# Select pane 1, set dir to api, run vim
tmux selectp -t 1
tmux send-keys "whoami" C-m

# Split pane 1 horizontal by 65%, start redis-server
tmux splitw -h -p 35
tmux send-keys "uname -a" C-m

# Select pane 2
tmux selectp -t 2
# Split pane 2 vertiacally by 25%
tmux splitw -v -p 75
tmux send-keys "ping 8.8.8.8" C=m


# select pane 3, set to api root
tmux selectp -t 3
tmux send-keys "dig google.com" C-m

# Select pane 1
tmux selectp -t 1

# create a new window called scratch
tmux new-window -t $session:1 -n scratch

# return to main vim window
tmux select-window -t $session:0

# Finished setup, attach to the tmux session!
tmux attach-session -t $session