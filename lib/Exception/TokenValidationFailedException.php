<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\UserOIDC\Exception;

use Exception;

class TokenValidationFailedException extends Exception {

	public function __construct(
		$message = '',
		private array $data = [],
		$code = 0,
		$previous = null,
	) {
		parent::__construct($message, $code, $previous);
	}

	public function getData(): array {
		return $this->data;
	}
}
