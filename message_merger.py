import argparse
import csv
import json
import os
import sys
from operator import itemgetter


def read_csv_file(file_path, unique_id):
    read_in_lines = []
    print(f'Reading csv file of {file_path}')
    with open(file_path, encoding='utf-8') as message_file:
        csv_reader = csv.reader(message_file, delimiter=',')
        for row in csv_reader:
            if row == ['ID', 'Timestamp', 'Contents', 'Attachments']:
                print(f'Skipping CSV header for file {file_path}')
            else:
                # Update the row with the unique id that will be the person receiving the message on their client
                if row[2] or row[3]:
                    row.append(unique_id)
                    read_in_lines.append(row)
    return read_in_lines


def write_csv_file(file_path, lines):
    print(f'Writing all server messages to {file_path}')
    with open(file_path, 'w', encoding='utf-8', newline='') as message_file:
        csv_writer = csv.writer(message_file, delimiter=',')
        csv_writer.writerows(lines)


def write_json_file(file_path, data):
    print(f'Writing server client config to {file_path}')
    with open(file_path, 'w', encoding='utf-8') as server_client_config:
        json.dump(data, server_client_config)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Load a directory of message files and combine them into a single file containing messages, message file name'
                                                 'must be in the format of "messages_<UID>", as this will determine who gets what messages')
    parser.add_argument('-i', '--input', type=str, required=True, help='Full path to the input directory containing the set of message files')
    parser.add_argument('-o', '--output', type=str, required=True, help='Full path to the input directory containing the set of message files')

    args = parser.parse_args()

    all_lines = []
    uid_list = []

    if not os.path.isdir(args.output):
        print('Specify a valid output directory')
        sys.exit(-1)

    if os.path.isdir(args.input):
        for root, directories, files in os.walk(args.input):
            for filename in files:
                try:
                    filename_parts = filename.split('_')
                    if len(filename_parts) > 1:
                        uid = filename_parts[-1][:-4]  # remove the .csv that should be at the end of the filename here
                    else:
                        uid = filename_parts[0][:-4]  # remove the .csv that should be at the end of the filename here

                    if uid not in uid_list:
                        uid_list.append(uid)
                    else:
                        print('Message file found with duplicate uid - exiting')
                        sys.exit(-1)

                    all_lines.extend(read_csv_file(os.path.join(root, filename), uid))
                except Exception as e:
                    print(f"Something went wrong {e}")
    else:
        print(f'{args.input} is not a valid directory, check that it exists or that you input it correctly')
        sys.exit(-1)

    # Now that all the messages have been loaded, its time to sort them in ascending order and add the CSV header back to the top of the list
    # and the output the new CSV file along with a JSON file to be loaded by the server to determine how many clients should be connected to rebuild the chat
    all_lines = sorted(all_lines, key=itemgetter(0))
    all_lines = [['ID', 'Timestamp', 'Contents', 'Attachments', 'UID']] + all_lines

    output_messages_path = os.path.join(args.output, 'all_messages.csv')
    write_csv_file(output_messages_path, all_lines)

    output_config_path = os.path.join(args.output, 'server_client_config.json')
    write_json_file(output_config_path, {'clients': uid_list})

    print('Successfully built server message file and server config')
