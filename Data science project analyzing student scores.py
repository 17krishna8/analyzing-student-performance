
# Import required libraries
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Ask user how many students to enter
n = int(input("Enter the number of students: "))
... 
... # Initialize empty lists
... student_ids = []
... math_scores = []
... science_scores = []
... 
... # Take user input
... for i in range(1, n + 1):
...     print(f"\nEnter details for student {i}:")
...     student_ids.append(i)
...     math = float(input("Enter Math Score: "))
...     science = float(input("Enter Science Score: "))
...     math_scores.append(math)
...     science_scores.append(science)
... 
... # Create DataFrame
... data = {
...     'Student_ID': student_ids,
...     'Math_Score': math_scores,
...     'Science_Score': science_scores
... }
... 
... df = pd.DataFrame(data)
... 
... # Display basic information about the dataset
... print("\nDataset Overview:")
... print(df.head())
... 
... print("\nBasic Statistics:")
... print(df.describe())
... 
... # Optional: visualize the data
... plt.figure(figsize=(8, 5))
... plt.scatter(df['Math_Score'], df['Science_Score'], color='blue')
... plt.title('Math vs Science Scores')
... plt.xlabel('Math Score')
... plt.ylabel('Science Score')
... plt.grid(True)
... plt.show()

