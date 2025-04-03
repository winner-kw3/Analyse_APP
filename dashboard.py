import dash
from dash import dcc, html
import dash_bootstrap_components as dbc
import json
import pandas as pd
import plotly.express as px
from dash.dependencies import Input, Output
import subprocess

# Charger les données JSON
with open('main.json') as f:
    data = json.load(f)

ips = []
for item in data['analysis_results']:
    ips.append({
        'ip': item['ip'],
        'reputation': item['reputation'],
        'country': item['country'],
        'as_owner': item['as_owner'],
        'total_packets': item['total_packets'],
        'classification': item['classification'],
        'connection_type': item['connection_type'],
        'last_analysis_date': item['last_analysis_date'],
        'malicious': item['last_analysis_stats']['malicious'],
        'suspicious': item['last_analysis_stats']['suspicious'],
        'undetected': item['last_analysis_stats']['undetected'],
        'harmless': item['last_analysis_stats']['harmless'],
        'timeout': item['last_analysis_stats']['timeout'],
        'first_seen': item['activity_period']['first_seen'],
        'last_seen': item['activity_period']['last_seen']
    })

df = pd.DataFrame(ips)

app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

sidebar = html.Div([
    html.H2("DASHBOARD", className='text-white text-center mt-3'),
    html.Hr(),
    html.Button(id="run_script", style={'display': 'none'}),
    dbc.Nav([
        dbc.NavLink("Accueil", href="#", id="btn-home", className='text-white'),
        dbc.NavLink("Graphiques", href="#", id="btn-graphs", className='text-white'),
        dbc.NavLink("Analyse", href="#", id="btn-analysis", className='text-white'),
        dbc.NavLink("Recap", href="#", id="btn-recap", className='text-white'),
        dbc.NavLink("Adresse IP", href="#", id="btn-settings", className='text-white'),
    ], vertical=True, pills=True, className='nav flex-column px-3')
], style={
    'width': '280px', 'backgroundColor': '#162447', 'height': '100vh', 'position': 'fixed',
    'top': '0', 'left': '0', 'padding': '20px'
})

content = html.Div(id='page-content', children=[], style={'marginLeft': '260px', 'padding': '20px'})

app.layout = html.Div([
    sidebar,
    content,
    html.Div(id='run_button')
], style={'display': 'flex', 'backgroundColor': '#1A1A2E'})

@app.callback(
    Output("page-content", "children"),
    [Input("btn-home", "n_clicks"), Input("btn-graphs", "n_clicks"),
     Input("btn-analysis", "n_clicks"), Input("btn-settings", "n_clicks"),
     Input("btn-recap", "n_clicks")]
)

def display_page(n_home, n_graphs, n_analysis, n_settings, n_recap):
    # ctx = dash.callback_context
    # if not ctx.triggered:
    #     return html.H1("Bienvenue sur le Dashboard", className='text-center text-white')
    # button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    ctx = dash.callback_context
    if not ctx.triggered:
        return dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Analyse de Logs"),
                        dbc.CardBody(
                            children=[
                                html.Div(
                                    children=[
                                        html.Button("Exécuter l'analyse", id="run_script", n_clicks=0, className="btn btn-primary")
                                    ],
                                    style={
                                        'display': 'flex',
                                        'justify-content': 'center',
                                        'align-items': 'center',
                                        'width': '100vh'  # Cette propriété aide à centrer verticalement
                                    }
                                ),
                                html.Div(id="output-script")
                            ]
                        ),
                    ]),
                ], width=12)
            ]),

            dbc.Row([
                dbc.Col([
                    html.P("© 2025 Analyse de Logs PCAP. Tous droits réservés.", className="text-center text-muted my-4")
                ], width=12)
            ])
        ])
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if button_id == "btn-graphs":
        return dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Réputation des IPs", className='text-center text-white'),
                            dcc.Graph(
                                id='reputation_graph',
                                figure=px.bar(df, x='ip', y='reputation', title="Réputation des IPs",
                                              color='reputation', color_continuous_scale='plasma')
                            )
                        ])
                    ], className='shadow-lg p-3 mb-5 bg-dark rounded')
                ], width=12),

                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Classification des IPs", className='text-center text-white'),
                            dcc.Graph(
                                id='classification_graph',
                                figure=px.pie(df, names='classification', title="Classification des IPs",
                                              color_discrete_sequence=px.colors.sequential.Magma)
                            )
                        ])
                    ], className='shadow-lg p-3 mb-5 bg-dark rounded')
                ], width=12)
            ])
        ])
    
    elif button_id == "btn-analysis":
        return dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Statistiques d'Analyse", className='text-center text-white'),
                            dcc.Graph(
                                id='analysis_stats_graph',
                                figure=px.bar(df, x='ip', y=['malicious', 'suspicious', 'undetected', 'harmless'],
                                            title="Statistiques d'Analyse des IPs", barmode='stack',
                                            color_discrete_sequence=px.colors.sequential.Viridis),
                                config={'displayModeBar': False},  # Optionnel pour désactiver la barre d'outils
                                style={'height': '80vh', 'width' : '80vh' }  # Augmente la taille du graphique (environ 80% de la hauteur de la fenêtre)
                            )
                        ])
                    ], className='shadow-lg p-3 mb-5 bg-dark rounded')
                ], width=12)  # Remplacer width=19 par width=12 pour occuper toute la largeur disponible
            ])
        ])
    
    elif button_id == "btn-recap":
        return dbc.Container([
            # Row for the table
            dbc.Row([
                dbc.Col([
                    # Card container for better styling
                    dbc.Card([
                        dbc.CardHeader("Détails des IPs", className='bg-dark text-white text-center'),
                        dbc.CardBody([
                            # Table with reduced size
                            dbc.Table.from_dataframe(
                                df[['ip', 'reputation', 'country', 'as_owner', 'total_packets', 'classification', 
                                    'connection_type', 'last_analysis_date', 'first_seen', 'last_seen',
                                    'malicious', 'suspicious', 'undetected', 'harmless', 'timeout']],
                                striped=True, bordered=True, hover=True,
                                style={"maxHeight": "400px", "overflowY": "hidden", "fontSize": "12px"}  # Reduced table size
                            )
                        ])
                    ], className='shadow-lg p-3 mb-5 bg-dark rounded')
                ], width=12)
            ])    ])
    
    elif button_id == "x":
        return dbc.Container([
            dbc.Row([
                    dbc.Col(
                        dbc.Card([
                            dbc.CardHeader("Annalyse de Logs"),
                            dbc.CardBody(
                                html.Button("Exécuter l'analyse", id="run_script", n_clicks=0, className="btn btn-primary"),
                                html.Div(id="output-script")
                            ),
                        ]),
                        width=12
                    )
                ]),
        ])

    

    # Tableau des IPs avec toutes les informations

    elif button_id == "btn-settings":
        return dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Détails des IPs"),
                        dbc.CardBody([
                            html.H4(f"Nombre total d'adresses IP: {df.shape[0]}", className='text-center text-white'),
                            dbc.Table.from_dataframe(
                                df[['ip']],
                                striped=True, bordered=True, hover=True
                            )
                        ])
                    ])
                ], width=12)
            ])
        ])

    return html.H1("Bienvenue sur le Dashboard", className='text-center text-white')
    


@app.callback(
    Output("output-script", "children"),
    Input("run_script", "n_clicks")
)
def run_script(n_clicks):
    if n_clicks > 0:
        try:
            result = subprocess.run(["python", "app.py"], capture_output=True, text=True)
            return html.Pre(result.stdout + result.stderr)
        except Exception as e:
            return html.Pre(str(e))
    return ""

if __name__ == '__main__':
    app.run(debug=True)
