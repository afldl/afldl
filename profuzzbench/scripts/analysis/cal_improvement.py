#!/usr/bin/env python3

import argparse
import pandas as pd

def main(csv_file, test_fuzzer, out_file):
    df = pd.read_csv(csv_file)

    # print(df)

    df['time'] = pd.to_datetime(df['time'], errors='coerce')
    # print(df)

    df.sort_values(by=['fuzzer', 'run', 'time'], ascending=[True, True, False], inplace=True)

    latest_data = df.groupby(['fuzzer', 'run']).head(4)
    # print(latest_data)

    average_cov = latest_data.groupby(['fuzzer', 'cov_type'])['cov'].mean().reset_index()

    # print("Fuzzer and Run Combinations with Average Cov:")
    # print(average_cov)
    # print(type(average_cov))

    b_abs, b_per, l_abs, l_per = 0,0,0,0
    b_abs_str, b_per_str, l_abs_str, l_per_str = "b_abs", "b_per", "l_abs", "l_per"  
    types = [b_abs_str, b_per_str, l_abs_str, l_per_str]
    data = {b_abs_str:b_abs,b_per_str:b_per,l_abs_str:l_abs,l_per_str:l_per}

    improve_list = []
    for index, row in average_cov.iterrows():
        if row['fuzzer'] == test_fuzzer: 
            for type_str in types:
                if row['cov_type'] ==  type_str:
                    data[type_str] = row['cov']


    for index, row in average_cov.iterrows():
        item = ( data[row['cov_type']] - row['cov'] ) /  data[row['cov_type']]
        improve_list.append(item * 100)

    # print(improve_list)
    average_cov['improv %'] = improve_list
    average_cov.to_csv(out_file, index=False)


    # print(data)




# Parse the input arguments
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('-i','--csv_file',type=str,required=True,help="Full path to results.csv")
    parser.add_argument('-o','--out_file',type=str,required=True,help="Output file")
    parser.add_argument('-t','--test_fuzzer',type=str,required=True,help="test_fuzzer")
    args = parser.parse_args()
    main(args.csv_file, args.test_fuzzer, args.out_file)
