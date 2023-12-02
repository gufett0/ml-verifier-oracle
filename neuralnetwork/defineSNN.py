#%%
import torch
import torch.nn as nn

# Define the Siamese neural network
class SiameseBambooNN(nn.Module):
    def __init__(self):
        super(SiameseBambooNN, self).__init__()
        self.embedding_net = nn.Sequential(
            nn.Conv2d(1, 8, kernel_size=3),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2),
            nn.Conv2d(8, 16, kernel_size=3),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2),
            nn.Flatten(),
            nn.Linear(16, 64),
            nn.ReLU(),
            nn.Linear(64, 16)
        )
        self.fc = nn.Linear(16, 1)  # Output 1 for similar, 0 for dissimilar

    def forward_one(self, x):
        x = x.view(-1, 1, 10, 10)  # Reshape input for convolutional layer
        return self.embedding_net(x)

    def forward(self, x1, x2):
        output1 = self.forward_one(x1)
        output2 = self.forward_one(x2)
        distance = torch.abs(output1 - output2)
        output = self.fc(distance)
        return output
