#!/usr/bin/env python3

import argparse
from pandas import read_csv
from pandas import DataFrame
from pandas import Grouper
from matplotlib import pyplot as plt
import pandas as pd


def main(csv_file, put, runs, cut_off, step, out_file):
  #Read the results
  df = read_csv(csv_file)


  #Calculate the mean of code coverage
  #Store in a list first for efficiency
  mean_list = []

  for subject in [put]:
    for fuzzer in ['aflnet', 'aflnwe','aflml']:
      for cov_type in ['b_abs', 'b_per', 'l_abs', 'l_per']:
        #get subject & fuzzer & cov_type-specific dataframe
        df1 = df[(df['subject'] == subject) & 
                         (df['fuzzer'] == fuzzer) & 
                         (df['cov_type'] == cov_type)]

        mean_list.append((subject, fuzzer, cov_type, 0, 0.0))
        for time in range(1, cut_off + 1, step):
          cov_total = 0
          run_count = 0

          for run in range(1, runs + 1, 1):
            #get run-specific data frame
            df2 = df1[df1['run'] == run]
            # print(df2.head())
            #get the starting time for this run
            start = df2.iloc[0, 0]

            #get all rows given a cutoff time
            df3 = df2[df2['time'] <= start + time*60]
            
            #update total coverage and #runs
            cov_total += df3.tail(1).iloc[0, 5]
            run_count += 1
          
          #add a new row
          mean_list.append((subject, fuzzer, cov_type, time, cov_total / run_count))

  #Convert the list to a dataframe
  mean_df = pd.DataFrame(mean_list, columns = ['subject', 'fuzzer', 'cov_type', 'time', 'cov'])

  fig, axes = plt.subplots(2, 2, figsize = (20, 10))
  fig.suptitle("Code coverage analysis")

  # for key, grp in mean_df.groupby(['fuzzer', 'cov_type']):
  #   if key[1] == 'b_abs':
  #     axes[0, 0].plot(grp['time'], grp['cov'])
  #     #axes[0, 0].set_title('Edge coverage over time (#edges)')
  #     axes[0, 0].set_xlabel('Time (in min)')
  #     axes[0, 0].set_ylabel('#edges')
  #   if key[1] == 'b_per':
  #     axes[1, 0].plot(grp['time'], grp['cov'])
  #     #axes[1, 0].set_title('Edge coverage over time (%)')
  #     axes[1, 0].set_ylim([0,100])
  #     axes[1, 0].set_xlabel('Time (in min)')
  #     axes[1, 0].set_ylabel('Edge coverage (%)')
  #   if key[1] == 'l_abs':
  #     axes[0, 1].plot(grp['time'], grp['cov'])
  #     #axes[0, 1].set_title('Line coverage over time (#lines)')
  #     axes[0, 1].set_xlabel('Time (in min)')
  #     axes[0, 1].set_ylabel('#lines')
  #   if key[1] == 'l_per':
  #     axes[1, 1].plot(grp['time'], grp['cov'])
  #     #axes[1, 1].set_title('Line coverage over time (%)')
  #     axes[1, 1].set_ylim([0,100])
  #     axes[1, 1].set_xlabel('Time (in min)')
  #     axes[1, 1].set_ylabel('Line coverage (%)')

  # for i, ax in enumerate(fig.axes):
  #   ax.legend(('AFLNet', 'AFLNwe','AFLml'), loc='upper left')
  #   ax.grid()



  # 假设mean_df已经定义并包含了必要的数据

  for key, grp in mean_df.groupby(['fuzzer', 'cov_type']):
      label = key[0]  # 使用'fuzzer'作为图例标签
      
      if key[1] == 'b_abs':
          axes[0, 0].plot(grp['time'], grp['cov'], label=label)
          axes[0, 0].set_xlabel('Time (in min)')
          axes[0, 0].set_ylabel('#edges')
      elif key[1] == 'b_per':
          axes[1, 0].plot(grp['time'], grp['cov'], label=label)
          axes[1, 0].set_ylim([0, 100])
          axes[1, 0].set_xlabel('Time (in min)')
          axes[1, 0].set_ylabel('Edge coverage (%)')
      elif key[1] == 'l_abs':
          axes[0, 1].plot(grp['time'], grp['cov'], label=label)
          axes[0, 1].set_xlabel('Time (in min)')
          axes[0, 1].set_ylabel('#lines')
      elif key[1] == 'l_per':
          axes[1, 1].plot(grp['time'], grp['cov'], label=label)
          axes[1, 1].set_ylim([0, 100])
          axes[1, 1].set_xlabel('Time (in min)')
          axes[1, 1].set_ylabel('Line coverage (%)')

  # 遍历所有子图并设置图例和网格线
  for ax in fig.axes:
      handles, labels = ax.get_legend_handles_labels()  # 获取当前轴上的所有句柄和标签
      unique_labels = []
      unique_handles = []
      for handle, label in zip(handles, labels):
          if label not in unique_labels:  # 确保图例中的标签唯一
              unique_labels.append(label)
              unique_handles.append(handle)
      ax.legend(unique_handles, unique_labels, loc='upper left')  # 设置图例位置为左上角
      ax.grid(True)  # 在每个子图上添加网格线

  #Save to file
  plt.savefig(out_file)



# Parse the input arguments
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('-i','--csv_file',type=str,required=True,help="Full path to results.csv")
    parser.add_argument('-p','--put',type=str,required=True,help="Name of the subject program")
    parser.add_argument('-r','--runs',type=int,required=True,help="Number of runs in the experiment")
    parser.add_argument('-c','--cut_off',type=int,required=True,help="Cut-off time in minutes")
    parser.add_argument('-s','--step',type=int,required=True,help="Time step in minutes")
    parser.add_argument('-o','--out_file',type=str,required=True,help="Output file")
    args = parser.parse_args()
    main(args.csv_file, args.put, args.runs, args.cut_off, args.step, args.out_file)
