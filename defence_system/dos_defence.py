"""
Module Name: dos_defence.py

This module defines all the functions that are used to detect and defend against
Denial of Service (DoS) attacks. It includes functions for training machine learning based
DoS detection model, acquiring all the features when a request is received, and
implementing a blocking strategy for the detect and defend against DoS attacks.
"""

import os
import pickle
import threading
import time
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn import svm
from sklearn.metrics import ConfusionMatrixDisplay, accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# define a ip status dict
ip_status = defaultdict(
    lambda: {
        "flow_duration": [],
        "timestamp": [],
        "packet_size": [],
        "last_time": None,
        "active_duration": [],
        "idle_duration": [],
    }
)

# define blacklist
blacklist = {}
# define greylist
greylist = {}
# define number of requests
num_requests = defaultdict(list)


def get_packets_per_second(ip):
    """get the packets per second of the ip.
    Args:
        ip (str): the ip address
    Returns:
        packets_per_second (float): the packets per second of the ip
    """
    timestamp = ip_status[ip]["timestamp"]
    # only get the 2 timestamps
    if len(timestamp) < 2:
        return 0
    duration = timestamp[-1] - timestamp[0]
    # get the packets count
    packets = len(timestamp)
    # get the packets per second
    if duration > 0:
        packets_per_second = packets / duration
    else:
        packets_per_second = 0
    return packets_per_second


def get_iat_mean(ip):
    """get the mean value of inter-arrival time of the ip.
    Args:
        ip (str): the ip address
    Returns:
        iat (float): the mean inter-arrival time of the ip
    """
    # get the inter-arrival time of the ip
    timestamp = ip_status[ip]["timestamp"]
    if len(timestamp) < 2:
        return 0
    iat = np.mean(np.diff(timestamp))  # calculate the inter-arrival time
    return iat


def get_iat_std(ip):
    """get the standard deviation of inter-arrival time of the ip.
    Args:
        ip (str): the ip address
    Returns:
        iat (float): the std inter-arrival time of the ip
    """
    # get the inter-arrival time of the ip
    timestamp = ip_status[ip]["timestamp"]
    if len(timestamp) < 2:
        return 0
    iat = np.std(np.diff(timestamp))  # calculate the inter-arrival time
    return iat


def get_avg_packet_size(ip):
    """get the average packet size of the ip.
    Args:
        ip (str): the ip address
    Returns:
        avg_packet_size (float): the average packet size of the ip
    """
    packet_size = ip_status[ip]["packet_size"]
    if len(packet_size) < 1:
        return 0
    avg_packet_size = np.mean(packet_size)
    return avg_packet_size


def get_active_mean(ip):
    """get the mean value of active time of the ip.
    Args:
        ip (str): the ip address
    Returns:
        active_mean (float): the mean active time of the ip
    """
    active_time = ip_status[ip]["active_duration"]
    if len(active_time) < 1:
        return 0
    active_mean = np.mean(active_time)
    return active_mean


def get_active_std(ip):
    """get the standard deviation of active time of the ip.
    Args:
        ip (str): the ip address
    Returns:
        active_std (float): the std active time of the ip
    """
    active_time = ip_status[ip]["active_duration"]
    if len(active_time) < 1:
        return 0
    active_std = np.std(active_time)
    return active_std


def get_idle_mean(ip):
    """get the mean value of idle time of the ip.
    Args:
        ip (str): the ip address
    Returns:
        idle_mean (float): the mean idle time of the ip
    """
    idle_time = ip_status[ip]["idle_duration"]
    if len(idle_time) < 1:
        return 0
    idle_mean = np.mean(idle_time)
    return idle_mean


def get_idle_std(ip):
    """get the standard deviation of idle time of the ip.
    Args:
        ip (str): the ip address
    Returns:
        idle_std (float): the std idle time of the ip
    """
    idle_time = ip_status[ip]["idle_duration"]
    if len(idle_time) < 1:
        return 0
    idle_std = np.std(idle_time)
    return idle_std


def get_request_features(ip):
    """get all the features that used to detect DoS attack.
    Args:
        ip (str): the ip address
    Returns:
        features (list): the features of the ip
    """
    # get the flow duarion of the ip
    duration_mean = np.mean(ip_status[ip]["flow_duration"])
    total_packet_length = (
        ip_status[ip]["packet_size"][-1] if ip_status[ip]["packet_size"] else 0
    )
    packet_s = get_packets_per_second(ip)
    iat_mean = get_iat_mean(ip)
    iat_std = get_iat_std(ip)
    avg_packet_size = get_avg_packet_size(ip)
    active_mean = get_active_mean(ip)
    active_std = get_active_std(ip)
    idle_mean = get_idle_mean(ip)
    idle_std = get_idle_std(ip)

    features = [
        duration_mean,
        total_packet_length,
        packet_s,
        iat_mean,
        iat_std,
        avg_packet_size,
        active_mean,
        active_std,
        idle_mean,
        idle_std,
    ]
    return features


def check_ip(ip):
    """check if the ip is in the blacklist.
    Args:
        ip (str): the ip address
    Returns:
        bool: True if the ip is in the blacklist, False otherwise
    """
    now = time.time()
    if ip in blacklist and now - blacklist[ip] < 0:  # IP is still in blacklist
        return True
    else:
        return False


def record_num_requests(ip, now, path, method):
    """record the number of requests from the ip.
    Args:
        ip (str): the ip address
        now (float): the current time
        path (str): the request path
        method (str): the request method
    Returns:
        num (int): the number of requests from the ip
    """
    if not (
        path == "/" and method == "POST"
    ):  # only record POST requests in the home page
        return len(num_requests[ip])
    num_requests[ip] = [t for t in num_requests[ip] if now - t < 60]
    num_requests[ip].append(now)
    num = len(num_requests[ip])
    return num


def block_strategy(ip, features, model, scale):
    """define the block strategy for the ip.
    Args:
        ip (str): the ip address
        features (list): the features of the ip
        model (object): the DoS detection model
        scale (object): the standard scaler
    Returns:
        bool: True if the ip is blocked, False otherwise
    """
    now = time.time()
    features = np.array(features)
    feature = scale.transform(features.reshape(1, -1))
    prediction = model.predict(feature)[0]

    if prediction == 1:
        # put the ip in the blacklist and block it for 10 minutes
        blacklist[ip] = now + 600
        print(f"The IP: {ip} is detected as a DoS attack")
        print(f"IP: {ip} is blocked")
        return True
    else:
        # put the ip in the greylist and block it for 1 minute
        greylist[ip] = greylist.get(ip, []) + [now]
        greylist[ip] = [t for t in greylist[ip] if now - t < 60]
        print(f"IP {ip} is in greylist")
        if len(greylist[ip]) > 5:
            # put the ip in the blacklist and block it for 10 minutes
            blacklist[ip] = now + 600
            print(f"Too many requests from the IP: {ip}")
            print(f"IP: {ip} is blocked")
            del greylist[ip]
            return True

    return False


def clean_list():
    """clean the blacklist and greylist every 30 seconds."""
    while True:
        now = time.time()
        # clean the blacklist
        ip_to_remove_b = [ip for ip, t in blacklist.items() if now - t > 0]
        for ip in ip_to_remove_b:
            del blacklist[ip]

        # clean the greylist
        ip_to_remove_g = [
            ip for ip, times in greylist.items() if all(now - t > 0 for t in times)
        ]
        for ip in ip_to_remove_g:
            del greylist[ip]
        # sleep for 30 seconds
        time.sleep(30)


def clean_strategy():
    """start a thread to clean the blacklist and greylist every 30 seconds."""
    thread_cleaning = threading.Thread(target=clean_list, daemon=True)
    thread_cleaning.start()


def dos_data_acq(file_path):
    """acquire the DoS dataset from the file path.
    Args:
        file_path (str): the file path of the dataset
    Returns:
        dataset (pd.DataFrame): the DoS dataset
    """
    dataset = pd.read_csv(file_path)
    return dataset


def standardize_data(x_train, x_val):
    """standardize the data using StandardScaler.
    Args:
        x_train (pd.DataFrame): the training data
        x_val (pd.DataFrame): the validation data
    Returns:
        x_train (np.ndarray): the standardized training data
        x_val (np.ndarray): the standardized validation data
        scaler (StandardScaler): the StandardScaler object
    """
    scaler = StandardScaler()
    x_train = scaler.fit_transform(x_train.values)
    x_val = scaler.transform(x_val.values)
    return x_train, x_val, scaler


def dos_data_preprocess(dataset: pd.DataFrame):
    """preprocess the DoS dataset, including modifying the label,
       splitting the data into train and test, and standardizing the data.
    Args:
        dataset (pd.DataFrame): the DoS dataset
    Returns:
        x_train (np.ndarray): the training data
        x_val (np.ndarray): the validation data
        y_train (np.ndarray): the training labels
        y_val (np.ndarray): the validation labels
        x_test (np.ndarray): the test data
        y_test (np.ndarray): the test labels
        scaler (StandardScaler): the StandardScaler object
    """
    x = dataset.drop(columns=[" Label"])
    y = dataset[" Label"]
    # process the label
    y = y.apply(lambda x: 0 if x == "BENIGN" else 1)

    # split the data into train and test
    x_train, x_val_test, y_train, y_val_test = train_test_split(
        x, y, test_size=0.2, random_state=42
    )
    x_val, x_test, y_val, y_test = train_test_split(
        x_val_test, y_val_test, test_size=0.5, random_state=42
    )
    # standardize the data
    x_train, x_val, scaler = standardize_data(x_train, x_val)
    x_test = scaler.transform(x_test.values)

    return x_train, x_val, y_train, y_val, x_test, y_test, scaler


def svm_model(x_train, y_train, x_val, y_val):
    """train the dos detection model based on SVM.
    Args:
        x_train (np.ndarray): the training data
        y_train (np.ndarray): the training labels
        x_val (np.ndarray): the validation data
        y_val (np.ndarray): the validation labels
    Returns:
        model (SVC): the trained SVM model
        acc_train (float): the training accuracy
        acc_val (float): the validation accuracy
    """
    model = svm.SVC(kernel="linear", C=1.0, random_state=711)
    model.fit(x_train, y_train)
    # evaluate the model
    y_pred_train = model.predict(x_train)
    acc_train = accuracy_score(y_train, y_pred_train)
    print(f"Train Accuracy: {acc_train}")
    y_pred_val = model.predict(x_val)
    acc_val = accuracy_score(y_val, y_pred_val)
    print(f"Validation Accuracy: {acc_val}")
    return model, acc_train, acc_val


def svm_predict(model, x_test, y_test):
    """predict the test data using the trained model.
    Args:
        model (SVC): the trained SVM model
        x_test (np.ndarray): the test data
        y_test (np.ndarray): the test labels
    Returns:
        accuracy (float): the test accuracy
        fig (plt.Figure): the confusion matrix figure
        ax (plt.Axes): the confusion matrix axes
    """
    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)
    fig, ax = plot_confusion_matrix(y_test, predictions)
    return accuracy, fig, ax


def plot_confusion_matrix(y_test, predictions):
    """plot the confusion matrix.
    Args:
        y_test (np.ndarray): the test labels
        predictions (np.ndarray): the predicted labels
    Returns:
        fig (plt.Figure): the confusion matrix figure
        ax (plt.Axes): the confusion matrix axes
    """
    cm = confusion_matrix(y_test, predictions, labels=[0, 1])
    cm_display_labels = ["Normal", "DoS"]
    fig, ax = plt.subplots(figsize=(7, 6))
    cm_display = ConfusionMatrixDisplay(
        confusion_matrix=cm, display_labels=cm_display_labels
    )
    cm_display.plot(ax=ax, cmap="Blues")
    return fig, ax


def build_dos_detection(filepath):
    """build the DoS detection model and save the model and scaler.
    Args:
        filepath (str): the file path of the dataset
    """
    dataset = dos_data_acq(filepath)
    x_train, x_val, y_train, y_val, x_test, y_test, scaler = dos_data_preprocess(
        dataset
    )
    model, _, _ = svm_model(x_train, y_train, x_val, y_val)
    acc_test, fig, _ = svm_predict(model, x_test, y_test)
    print(f"Test Accuracy: {acc_test}")
    # save the model, scaler and figure
    model_file = "./model"
    figure_file = "./figure"

    if not os.path.exists(model_file):
        os.makedirs(model_file)
    if not os.path.exists(figure_file):
        os.makedirs(figure_file)

    model_name = "SVM_model.pkl"
    scaler_name = "scaler.pkl"
    with open(os.path.join(model_file, model_name), "wb") as f:
        pickle.dump(model, f)
    with open(os.path.join(model_file, scaler_name), "wb") as f:
        pickle.dump(scaler, f)
    fig.savefig(os.path.join(figure_file, "confusion_matrix.png"))
