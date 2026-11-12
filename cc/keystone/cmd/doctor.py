# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Backport doctor's ignore support using the installed Keystone checks."""

from keystone.cmd import doctor
import keystone.conf
from keystone.i18n import _

CONF = keystone.conf.CONF


def diagnose():
    """Report all matching symptoms, returning true for any not ignored."""
    symptoms_found = False

    for symptom in doctor.gather_symptoms():
        if CONF.debug:
            print('Checking for {}...'.format(
                symptom.__name__[len(doctor.SYMPTOM_PREFIX):].replace('_', ' ')))

        if symptom():
            print(_('\nWARNING: %s') % _(symptom.__doc__))

            if symptom.__name__ in CONF.command.ignore:
                print(_('Symptom %s is ignored for the exit condition.') %
                      symptom.__name__)
            else:
                symptoms_found = True

    return symptoms_found
