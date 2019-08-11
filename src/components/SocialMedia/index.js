import React from 'react'
import PropTypes from 'prop-types'

import './styles.scss'
import Facebook from './Facebook'
import Twitter from './Twitter'
import Instagram from './Instagram/index'
import ColumnsGrid from '../ColumnsGrid/index'

const twitterURL = 'https://twitter.com/danielrahman_fi'
const facebookPage = 'danielalexanderrahman'

const SocialMedia = ({ sectionTitle }) => (
  <div className="social-media">
    <h2 className="social-media__title">{sectionTitle}</h2>
    <ColumnsGrid columns={3}>
      <Facebook facebookPage={facebookPage} />
      <Twitter twitterURL={twitterURL} />
      <Instagram />
    </ColumnsGrid>
  </div>
)

SocialMedia.propTypes = {
  sectionTitle: PropTypes.string,
}

SocialMedia.defaultProps = {
  sectionTitle: '',
}

export default SocialMedia
