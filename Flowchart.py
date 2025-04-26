import plotly.graph_objects as go

# Define the nodes
nodes = [
    "Generate PUF from RAM",
    "Stabilize PUF with ML Model",
    "Generate Seed from PUF",
    "Create Keystreams using Chaotic Algorithm",
    "Encrypt Data with XOR Keystreams",
    "Generate MAC and Nonce",
    "Base64 Encode Data",
    "Transmit Data to Server"
]

# Define the positions of the nodes
x_coords = [0.5, 0.5, 0.5, 0.5, 0.5, 1.5, 1.5, 1.5]
y_coords = [1.0, 0.8, 0.6, 0.4, 0.2, 0.6, 0.4, 0.2]

# Define the connections (arrows)
connections = [
    (0, 1),  # Generate PUF -> Stabilize PUF
    (1, 2),  # Stabilize PUF -> Generate Seed
    (2, 3),  # Generate Seed -> Create Keystreams
    (3, 4),  # Create Keystreams -> Encrypt Data
    (2, 5),  # Generate Seed -> Generate MAC
    (5, 6),  # Generate MAC -> Base64 Encode
    (6, 7)   # Base64 Encode -> Transmit Data
]

# Rectangle dimensions
node_width = 0.5
node_height = 0.1

# Create figure
fig = go.Figure()

# Add nodes as rounded rectangles with text annotations
for x, y, node in zip(x_coords, y_coords, nodes):
    # Add the rectangle
    fig.add_shape(
        type="rect",
        x0=x - node_width / 2, y0=y - node_height / 2,
        x1=x + node_width / 2, y1=y + node_height / 2,
        line=dict(color="black", width=2),
        fillcolor="lightblue",
        xref="x", yref="y",
    )
    # Add the text annotation
    fig.add_annotation(
        x=x, y=y,
        text=node,
        showarrow=False,
        font=dict(size=12),
        align="center",
        xref="x", yref="y",
    )

# Add arrows for the connections
for start, end in connections:
    x_start = x_coords[start]
    y_start = y_coords[start] - node_height / 2  # Bottom edge of the start rectangle
    x_end = x_coords[end]
    y_end = y_coords[end] + node_height / 2  # Top edge of the end rectangle
    fig.add_annotation(
        ax=x_start, ay=y_start,
        x=x_end, y=y_end,
        xref="x", yref="y", axref="x", ayref="y",
        showarrow=True,
        arrowhead=3,
        arrowsize=1.5,
        arrowwidth=2,
        arrowcolor="black"
    )

# Adjust the layout for better visibility
fig.update_layout(
    showlegend=False,
    xaxis=dict(showgrid=False, zeroline=False, visible=False),
    yaxis=dict(showgrid=False, zeroline=False, visible=False),
    margin=dict(l=20, r=20, t=20, b=20),
    height=600,
    width=900,
    paper_bgcolor="white"
)

# Display the flowchart
fig.show()
