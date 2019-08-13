import React, { Component } from "react"
import Instafeed from "instafeed.js"

import "./styles.scss"

class Instagram extends Component {
  loadInstagramLogin = () => {
    const feed = new Instafeed({
      get: "user",
      clientId: "015aca27da3f4ced83543e3ed4b7a9b7",
      accessToken: "2518978880.1677ed0.e2948d8b7e1e4ef9934abaed131e383d",
      userId: "18122855",
      template:
        '<a class="animation" target="_blank" href="{{link}}"><img src="{{image}}" /></a>',
    })
    feed.run()
  }

  render() {
    return (
      <div className="instagram-column">
        <h3 className="instagram-column__title">Instagram</h3>
        <div style={{ height: "590px", overflow: "hidden" }}>
          <iframe
            title="Janne's Instagram"
            src="//lightwidget.com/widgets/decfd76050a05b8c94ae883db7ee1a02.html"
            scrolling="yes"
            allowtransparency="true"
            class="lightwidget-widget"
            style={{ width: "100%", border: "0", overflow: "hidden" }}
          ></iframe>
        </div>
      </div>
    )
  }
}

export default Instagram
