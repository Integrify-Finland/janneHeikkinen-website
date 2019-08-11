import React, { Component } from 'react'
import Instafeed from 'instafeed.js'

import './styles.scss'

class Instagram extends Component {
  loadInstagramLogin = () => {
    const feed = new Instafeed({
      get: 'user',
      clientId: '015aca27da3f4ced83543e3ed4b7a9b7',
      accessToken: '18122855.015aca2.eeefbfe7bcea4a858a6d9859b26ed8ac',
      userId: '18122855',
      template:
        '<a class="animation" target="_blank" href="{{link}}"><img src="{{image}}" /></a>',
    })
    feed.run()
  }

  componentDidMount = () => {
    this.loadInstagramLogin()
  }

  render() {
    return (
      <div className="instagram-column">
        <h3 className="instagram-column__title">Instagram</h3>
        <div id="instafeed" />
      </div>
    )
  }
}

export default Instagram
