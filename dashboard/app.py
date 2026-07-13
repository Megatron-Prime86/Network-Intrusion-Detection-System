from flask import Flask
from flask import render_template

import json
import pandas as pd
import plotly.express as px


app = Flask(__name__)


@app.route("/")
def home():

    try:

        with open(
            "exports/alerts.json",
            "r"
        ) as file:

            alerts = json.load(file)

    except Exception:

        alerts = []

    total_alerts = len(alerts)

    attack_counts = {}

    for alert in alerts:

        attack = alert["attack"]

        attack_counts[attack] = (
            attack_counts.get(
                attack,
                0
            ) + 1
        )

    if attack_counts:

        df = pd.DataFrame(
            {
                "Attack":
                list(
                    attack_counts.keys()
                ),

                "Count":
                list(
                    attack_counts.values()
                )
            }
        )

        fig = px.pie(
            df,
            names="Attack",
            values="Count",
            title="Attack Distribution"
        )

        fig.update_layout(

            template="plotly_dark",

            paper_bgcolor=
            "rgba(0,0,0,0)",

            plot_bgcolor=
            "rgba(0,0,0,0)",

            font=dict(
                color="white"
            ),

            title_x=0.5
        )

        chart = fig.to_html(
            full_html=False,
            config={
                "displayModeBar": False
            }
        )

    else:

        chart = """
        <h3 style='text-align:center;color:white'>
        No Alert Data Available
        </h3>
        """

    return render_template(
        "index.html",
        total_alerts=total_alerts,
        alerts=alerts,
        chart=chart
    )


if __name__ == "__main__":

    app.run(
        debug=True
    )