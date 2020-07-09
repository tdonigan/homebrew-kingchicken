
VERSION_FILE := ./VERSION
VERSION := $(shell head -1 $(VERSION_FILE) | tr -d '\n')

