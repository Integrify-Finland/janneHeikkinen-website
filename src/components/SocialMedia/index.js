import React from 'react'
import PropTypes from 'prop-types'

import './styles.scss'
import Facebook from './Facebook'
import Twitter from './Twitter'
import Instagram from './Instagram/index'
import ColumnsGrid from '../ColumnsGrid/index'

const twitterURL = 'https://twitter.com/heikkinenjanne'
const facebookPage = 'janneheikkinenpage'

const SocialMedia = () => (
  <div className="social-media">
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
