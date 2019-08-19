import React, { Component } from "react"

import "./styles.scss"

class Instagram extends Component {
  render() {
    return (
      <div className="instagram-column">
        <h3 className="instagram-column__title">Instagram</h3>
        <div style={{ height: "590px", overflow: "hidden" }}>
          <iframe
<<<<<<< HEAD
            title="Janne's Instagram"
            src="https://www.juicer.io/api/feeds/charliefeatherlight/iframe"
            scrolling="yes"
            allowtransparency="true"
            class="lightwidget-widget"
            style={{ width: "100%", border: "0", overflow: "hidden", height: "580px" }}
=======
            title="Janne's Instagram feed"
            src="https://cdn.lightwidget.com/widgets/b697a021935e50f8b4656ecedebb7698.html"
            scrolling="no"
            allowtransparency="true"
            className="lightwidget-widget"
            style={{ width: "100%", border: "0", overflow: "hidden" }}
>>>>>>> 7855c19aed81e764f0cc0deed4013a030dbb8929
          ></iframe>
        </div>
      </div>
    )
  }
}

export default Instagram
