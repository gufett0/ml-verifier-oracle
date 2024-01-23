import torch
import torch.nn as nn
import torch.nn.functional as F

# Define the Siamese neural network
class FurtherAdjustedSiameseBambooNN(nn.Module):
    def __init__(self):
        super(FurtherAdjustedSiameseBambooNN, self).__init__()
        self.embedding_net = nn.Sequential(
            nn.Conv2d(1, 8, kernel_size=3),  # Reduce filters in the first Conv2d layer
            nn.BatchNorm2d(8),
            nn.ReLU(),
            nn.Flatten()
        )
        # Calculate the size of the fully connected layer input based on the spatial dimensions
        self.fc_input_size = self.get_fc_input_size((1, 10, 10))
        self.fc = nn.Sequential(
            nn.Linear(self.fc_input_size, 128),  # Reduce units in the first Linear layer
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 32)  # Reduce units in the second Linear layer
        )
        self.out = nn.Linear(32, 1)  # Output 1 for similar, 0 for dissimilar

    def forward_one(self, x):
        x = x.view(-1, 1, 10, 10)  # Reshape input for convolutional layer
        return self.embedding_net(x)

    def forward(self, x1, x2):
        output1 = self.forward_one(x1)
        output2 = self.forward_one(x2)
        distance = torch.abs(output1 - output2)
        embedded = self.fc(distance)
        output = self.out(embedded)
        return output

    def get_fc_input_size(self, shape):
        with torch.no_grad():
            x = torch.zeros(1, *shape)
            x = self.embedding_net(x)
            return x.view(1, -1).size(1)
