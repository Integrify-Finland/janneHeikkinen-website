/* eslint-disable no-underscore-dangle */
import React, { Component } from 'react'
import PropTypes from 'prop-types'

import './styles.scss'

class Twitter extends Component {
  loadTwitterLoginApi = () => {
    window.twttr = ((d, s, id) => {
      const fjs = d.getElementsByTagName(s)[0]
      const t = window.twttr || {}
      if (d.getElementById(id)) return t
      const js = d.createElement(s)
      js.id = id
      js.src = 'https://platform.twitter.com/widgets.js'
      fjs.parentNode.insertBefore(js, fjs)

      t._e = []
      t.ready = f => {
        t._e.push(f)
      }

      return t
    })(document, 'script', 'twitter-wjs')
  }

  componentDidMount = () => {
    this.loadTwitterLoginApi()
    return window.twttr.widgets && window.twttr.widgets.load()
  }

  render() {
    const { twitterURL } = this.props
    return (
      <div className="twitter-column">
        <h3 className="twitter-column__title">Twitter</h3>
        <a
          className="twitter-timeline"
          data-height="500"
          data-width="500"
          data-adapt-container-width="true"
          href={twitterURL}
          target="blank"
        >
          Tweets by Janne Heikkinen
        </a>
      </div>
    )
  }
}

Twitter.propTypes = {
  twitterURL: PropTypes.string.isRequired,
}

export default Twitter
